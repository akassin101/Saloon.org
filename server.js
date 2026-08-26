'use strict';

/**
 * Saloon Backend Server
 *
 * Provides shared, persistent data for the commons.html frontend.
 * Data is stored in data.json alongside this file — no database needed.
 *
 * Setup:
 *   cd saloon-backend
 *   npm install
 *   npm start          (or: npm run dev  for auto-restart on changes)
 *
 * Then open commons.html and set:
 *   const BACKEND_URL = 'http://localhost:3000';
 *
 * To deploy publicly (e.g. Railway, Render, Fly.io):
 *   - Set the PORT environment variable (most platforms do this automatically)
 *   - Set JWT_SECRET to a long random string (e.g. openssl rand -hex 32)
 *   - Set FRONTEND_ORIGIN to your frontend URL for CORS
 *   - Upload both server.js and package.json; run npm install && npm start
 */

const express   = require('express');
const cors      = require('cors');
const jwt       = require('jsonwebtoken');
const bcrypt    = require('bcryptjs');
const fs        = require('fs');
const path      = require('path');

const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();

app.use(helmet());
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
}));
const PORT   = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'saloon-dev-secret-change-in-production';
const DATA   = path.join(__dirname, 'data.json');
const ORIGIN = process.env.FRONTEND_ORIGIN || '*'; // restrict in production

// ─── PERSISTENCE ──────────────────────────────────────────────────────────────

let db = loadDB();

function loadDB() {
  try {
    if (fs.existsSync(DATA)) return JSON.parse(fs.readFileSync(DATA, 'utf8'));
  } catch(e) { console.error('Failed to load data.json:', e.message); }
  return { users: [], conversations: [], posts: [], comments: [], invitations: [] };
}

let _saveTimer = null;
function saveDB() {
  clearTimeout(_saveTimer);
  _saveTimer = setTimeout(() => {
    fs.writeFile(DATA, JSON.stringify(db, null, 2), err => {
      if (err) console.error('Failed to save data.json:', err.message);
    });
  }, 200);
}

function uid() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}

// ─── MIDDLEWARE ───────────────────────────────────────────────────────────────

app.use(cors({ origin: ORIGIN }));
app.use(express.json({ limit: '2mb' }));

// Serve the frontend file from the parent directory
app.use(express.static(path.join(__dirname, '..')));

// Auth middleware — hard-fails with 401
function requireAuth(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error: 'Not authenticated.' });
  try {
    req.user = jwt.verify(h.slice(7), SECRET);
    next();
  } catch(e) { res.status(401).json({ error: 'Session expired. Please sign in again.' }); }
}

// Auth middleware — passes through without a token (req.user may be undefined)
function optionalAuth(req, res, next) {
  const h = req.headers.authorization;
  if (h && h.startsWith('Bearer ')) {
    try { req.user = jwt.verify(h.slice(7), SECRET); } catch(e) {}
  }
  next();
}

// Strip password hash before sending a user object to the client
function pub(u) {
  const { passwordHash, ...safe } = u;
  return safe;
}

// ─── AUTH ─────────────────────────────────────────────────────────────────────

app.post('/api/auth/register', async (req, res) => {
  const { firstName, lastName, email, password, idFileName } = req.body;
  if (!firstName || !lastName || !email || !password)
    return res.status(400).json({ error: 'All fields are required.' });
  if (!email.includes('@'))
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  if (db.users.find(u => u.email === email.toLowerCase().trim()))
    return res.status(400).json({ error: 'An account with that email already exists.' });

  const passwordHash = await bcrypt.hash(password, 10);
  const user = {
    id: uid(),
    firstName: firstName.trim(),
    lastName: lastName.trim(),
    email: email.toLowerCase().trim(),
    passwordHash,
    idFileName: idFileName || '',
    idSubmitted: !!idFileName,
    verified: false,
    createdAt: Date.now(),
    bio: '', credentials: [], interests: [],
    recommendedBooks: [], recommendedFilms: [], following: []
  };

  // Auto-join any conversations this email was invited to
  const pending = db.invitations.filter(i => i.email === user.email);
  pending.forEach(inv => {
    const c = db.conversations.find(c => c.id === inv.convId);
    if (c && !c.participants.includes(user.id)) c.participants.push(user.id);
  });
  db.invitations = db.invitations.filter(i => i.email !== user.email);

  db.users.push(user);
  saveDB();

  const token = jwt.sign({ id: user.id }, SECRET, { expiresIn: '30d' });
  res.json({ user: pub(user), token });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.users.find(u => u.email === email?.toLowerCase()?.trim());
  if (!user) return res.status(400).json({ error: 'No account found with that email.' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(400).json({ error: 'Incorrect password.' });
  const token = jwt.sign({ id: user.id }, SECRET, { expiresIn: '30d' });
  res.json({ user: pub(user), token });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  res.json(pub(user));
});

// ─── DATA SNAPSHOT ────────────────────────────────────────────────────────────
// Returns everything the frontend needs to hydrate its local DB.
// Password hashes are never included.

app.get('/api/data', optionalAuth, (req, res) => {
  res.json({
    users:         db.users.map(pub),
    conversations: db.conversations,
    posts:         db.posts,
    comments:      db.comments,
    invitations:   db.invitations
  });
});

// ─── CONVERSATIONS ────────────────────────────────────────────────────────────

app.post('/api/conversations', requireAuth, (req, res) => {
  const { title, category, content } = req.body;
  if (!title || !category || !content)
    return res.status(400).json({ error: 'title, category, and content are required.' });
  if (title.length > 200)   return res.status(400).json({ error: 'Title too long (max 200 chars).' });
  if (content.length > 20000) return res.status(400).json({ error: 'Content too long (max 20 000 chars).' });

  const conv = {
    id: uid(), title, category,
    creatorId: req.user.id,
    participants: [req.user.id],
    createdAt: Date.now(), lastActivity: Date.now(),
    viewCount: 0, likes: [], dislikes: []
  };
  const post = {
    id: uid(), conversationId: conv.id,
    authorId: req.user.id, content, createdAt: Date.now()
  };
  db.conversations.push(conv);
  db.posts.push(post);
  saveDB();
  res.json({ conversation: conv, post });
});

app.patch('/api/conversations/:id', requireAuth, (req, res) => {
  const conv = db.conversations.find(c => c.id === req.params.id);
  if (!conv) return res.status(404).json({ error: 'Conversation not found.' });
  if (conv.creatorId !== req.user.id) return res.status(403).json({ error: 'Only the creator can edit this.' });
  if (req.body.title)    conv.title    = req.body.title;
  if (req.body.category) conv.category = req.body.category;
  saveDB();
  res.json(conv);
});

app.post('/api/conversations/:id/view', optionalAuth, (req, res) => {
  const conv = db.conversations.find(c => c.id === req.params.id);
  if (!conv) return res.status(404).json({ error: 'Not found.' });
  conv.viewCount = (conv.viewCount || 0) + 1;
  saveDB();
  res.json({ viewCount: conv.viewCount });
});

app.post('/api/conversations/:id/vote', requireAuth, (req, res) => {
  const conv = db.conversations.find(c => c.id === req.params.id);
  if (!conv) return res.status(404).json({ error: 'Not found.' });
  const userId = req.user.id;
  const { type } = req.body;
  conv.likes    = conv.likes    || [];
  conv.dislikes = conv.dislikes || [];

  if (type === 'like') {
    if (conv.likes.includes(userId)) {
      conv.likes = conv.likes.filter(x => x !== userId);
    } else {
      conv.likes.push(userId);
      conv.dislikes = conv.dislikes.filter(x => x !== userId);
    }
  } else {
    if (conv.dislikes.includes(userId)) {
      conv.dislikes = conv.dislikes.filter(x => x !== userId);
    } else {
      conv.dislikes.push(userId);
      conv.likes = conv.likes.filter(x => x !== userId);
    }
  }
  saveDB();
  res.json(conv);
});

app.post('/api/conversations/:id/participants', requireAuth, (req, res) => {
  const conv = db.conversations.find(c => c.id === req.params.id);
  if (!conv) return res.status(404).json({ error: 'Not found.' });
  if (!conv.participants.includes(req.user.id))
    return res.status(403).json({ error: 'Only participants can add others.' });

  const email = req.body.email?.toLowerCase()?.trim();
  if (!email) return res.status(400).json({ error: 'email is required.' });

  const target = db.users.find(u => u.email === email);
  if (!target) {
    const already = db.invitations.find(i => i.email === email && i.convId === conv.id);
    if (already) return res.status(400).json({ error: 'An invitation has already been sent to that address.' });
    db.invitations.push({ email, convId: conv.id, invitedBy: req.user.id, invitedAt: Date.now() });
    saveDB();
    return res.json({ invited: true });
  }
  if (conv.participants.includes(target.id))
    return res.status(400).json({ error: 'That person is already a participant.' });
  conv.participants.push(target.id);
  saveDB();
  res.json({ added: true, user: pub(target) });
});

// ─── POSTS ────────────────────────────────────────────────────────────────────

app.post('/api/posts', requireAuth, (req, res) => {
  const { conversationId, content } = req.body;
  if (!content || content.length > 20000)
    return res.status(400).json({ error: 'Content required and must be under 20 000 chars.' });
  const conv = db.conversations.find(c => c.id === conversationId);
  if (!conv) return res.status(404).json({ error: 'Conversation not found.' });
  if (!conv.participants.includes(req.user.id))
    return res.status(403).json({ error: 'You are not a participant in this conversation.' });
  const post = { id: uid(), conversationId, authorId: req.user.id, content, createdAt: Date.now() };
  db.posts.push(post);
  conv.lastActivity = Date.now();
  saveDB();
  res.json(post);
});

// ─── COMMENTS ─────────────────────────────────────────────────────────────────

app.post('/api/comments', requireAuth, (req, res) => {
  const { conversationId, postId, selectedText, content } = req.body;
  if (!conversationId || !content)
    return res.status(400).json({ error: 'conversationId and content are required.' });
  if (content.length > 5000) return res.status(400).json({ error: 'Comment too long (max 5 000 chars).' });
  const comment = {
    id: uid(), conversationId,
    postId:       postId       || null,
    authorId:     req.user.id,
    selectedText: selectedText || null,
    content,
    createdAt: Date.now()
  };
  db.comments.push(comment);
  saveDB();
  res.json(comment);
});

// ─── USERS ────────────────────────────────────────────────────────────────────

app.get('/api/users/:id', (req, res) => {
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  res.json(pub(user));
});

app.patch('/api/users/:id', requireAuth, (req, res) => {
  if (req.user.id !== req.params.id)
    return res.status(403).json({ error: 'You can only edit your own profile.' });
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  if (req.body.bio && req.body.bio.length > 1000)
    return res.status(400).json({ error: 'Bio too long (max 1 000 chars).' });
  const allowed = ['bio', 'credentials', 'interests', 'recommendedBooks', 'recommendedFilms'];
  allowed.forEach(k => { if (req.body[k] !== undefined) user[k] = req.body[k]; });
  saveDB();
  res.json(pub(user));
});

app.post('/api/users/:id/follow', requireAuth, (req, res) => {
  const follower = db.users.find(u => u.id === req.user.id);
  const targetId = req.params.id;
  if (!follower) return res.status(404).json({ error: 'User not found.' });
  if (follower.id === targetId) return res.status(400).json({ error: 'Cannot follow yourself.' });
  follower.following = follower.following || [];
  if (follower.following.includes(targetId)) {
    follower.following = follower.following.filter(x => x !== targetId);
  } else {
    follower.following.push(targetId);
  }
  saveDB();
  res.json({ following: follower.following.includes(targetId) });
});

// ─── START ────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log('');
  console.log('  🍺  Saloon backend running at http://localhost:' + PORT);
  console.log('');
  console.log('  To connect the frontend, open commons.html and set:');
  console.log('    const BACKEND_URL = \'http://localhost:' + PORT + '\';');
  console.log('');
  if (SECRET === 'saloon-dev-secret-change-in-production') {
    console.log('  ⚠️  WARNING: Using default JWT secret. Set JWT_SECRET env var before deploying.');
    console.log('     e.g.  JWT_SECRET=$(openssl rand -hex 32) node server.js');
    console.log('');
  }
});
