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

const express    = require('express');
const cors       = require('cors');
const jwt        = require('jsonwebtoken');
const bcrypt     = require('bcryptjs');
const fs         = require('fs');
const path       = require('path');
const https      = require('https');
const crypto     = require('crypto');

const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();

app.set('trust proxy', 1);
app.use(helmet());
const PORT        = process.env.PORT || 3000;
const IS_PROD     = process.env.NODE_ENV === 'production' || !!process.env.RAILWAY_ENVIRONMENT;
const SECRET      = process.env.JWT_SECRET || 'saloon-dev-secret-change-in-production';
const DATA        = process.env.DATA_PATH || path.join(__dirname, 'data.json');
const ORIGIN      = process.env.FRONTEND_ORIGIN
  ? process.env.FRONTEND_ORIGIN.split(',').map(s => s.trim())
  : '*';
const SITE_URL    = process.env.SITE_URL || 'https://saloon.org';
const FROM_EMAIL  = process.env.FROM_EMAIL || 'noreply@saloon.org';
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || 'akassin101@gmail.com').toLowerCase().trim();
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID
  || '233389892795-7nklhha46ahv3odsn0uk0lu69qcogakb.apps.googleusercontent.com';

// How long after posting an author may still edit or delete their own post.
const EDIT_WINDOW_MS = 24 * 60 * 60 * 1000;
// Must match the '24 hours' the verification email promises.
const EMAIL_VERIFY_TTL_MS = 24 * 60 * 60 * 1000;

// ─── SECRET GUARDS ────────────────────────────────────────────────────────────
// Refuse to boot in production with the public placeholder secrets. These values
// live in a public repo — running with them means anyone can forge sessions or
// call the admin API.

const ADMIN_SECRET = process.env.ADMIN_SECRET || 'saloon-admin-change-this';

if (IS_PROD) {
  const insecure = [];
  if (SECRET === 'saloon-dev-secret-change-in-production') insecure.push('JWT_SECRET');
  if (ADMIN_SECRET === 'saloon-admin-change-this')         insecure.push('ADMIN_SECRET');
  if (insecure.length) {
    console.error(`\n  FATAL: refusing to start in production with default ${insecure.join(' and ')}.`);
    console.error('  Generate strong values (openssl rand -hex 32) and set them as env vars.\n');
    process.exit(1);
  }
  if (SECRET === ADMIN_SECRET) {
    console.error('\n  FATAL: JWT_SECRET and ADMIN_SECRET must be different values.\n');
    process.exit(1);
  }
  // Without this the CORS origin silently falls back to '*' if the env var is
  // ever dropped from a redeploy or a new environment.
  if (!process.env.FRONTEND_ORIGIN)
    console.warn('  WARNING: FRONTEND_ORIGIN is unset — CORS is falling back to "*".');
}

// ─── EMAIL ─────────────────────────────────────────────────────────────────────

const RESEND_KEY = process.env.RESEND_API_KEY;

async function sendMail(to, subject, html) {
  if (!RESEND_KEY) {
    console.log(`[email] To: ${to}\nSubject: ${subject}\n${html.replace(/<[^>]+>/g,'')}`);
    return;
  }
  const body = JSON.stringify({ from: FROM_EMAIL, to, subject, html });
  await new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'api.resend.com',
      path: '/emails',
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${RESEND_KEY}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      }
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve();
        } else {
          reject(new Error(`Resend API ${res.statusCode}: ${data}`));
        }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ─── PERSISTENCE ──────────────────────────────────────────────────────────────

let db = loadDB();

function loadDB() {
  const empty = { users: [], conversations: [], posts: [], comments: [], invitations: [] };
  if (!fs.existsSync(DATA)) return empty;
  try {
    const parsed = JSON.parse(fs.readFileSync(DATA, 'utf8'));
    return Object.assign(empty, parsed);
  } catch(e) {
    // Never silently start empty on a corrupt file — the first saveDB() would
    // overwrite it and destroy any chance of recovery. Preserve it and stop.
    const backup = `${DATA}.corrupt-${Date.now()}`;
    try { fs.copyFileSync(DATA, backup); } catch(_) {}
    console.error(`\n  FATAL: ${DATA} is unreadable (${e.message}).`);
    console.error(`  A copy was preserved at ${backup}. Fix or remove the file, then restart.\n`);
    process.exit(1);
  }
}

// Writes are debounced, but a sustained stream of requests must not starve the
// write forever — _saveDeadline forces a flush at most MAX_SAVE_DELAY after the
// first pending change. The write itself goes to a temp file and is renamed into
// place, so a crash mid-write can never truncate data.json.
const MAX_SAVE_DELAY = 2000;
let _saveTimer    = null;
let _saveDeadline = 0;
let _writing      = false;
let _writeAgain   = false;

function flushDB() {
  if (_writing) { _writeAgain = true; return; }
  _writing = true;
  _saveTimer = null;
  _saveDeadline = 0;
  const tmp = DATA + '.tmp';
  fs.writeFile(tmp, JSON.stringify(db, null, 2), err => {
    if (err) {
      console.error('Failed to write data:', err.message);
      _writing = false;
      if (_writeAgain) { _writeAgain = false; saveDB(); }
      return;
    }
    fs.rename(tmp, DATA, err2 => {
      if (err2) console.error('Failed to commit data:', err2.message);
      _writing = false;
      if (_writeAgain) { _writeAgain = false; saveDB(); }
    });
  });
}

function saveDB() {
  const now = Date.now();
  if (!_saveDeadline) _saveDeadline = now + MAX_SAVE_DELAY;
  clearTimeout(_saveTimer);
  _saveTimer = setTimeout(flushDB, Math.max(0, Math.min(200, _saveDeadline - now)));
}

// ─── MIGRATIONS ───────────────────────────────────────────────────────────────
// Each runs at most once; db.meta records which have already been applied.

db.meta = db.meta || {};

// Migrate existing users created before email verification was added
db.users.forEach(u => { if (u.emailVerified === undefined) u.emailVerified = true; });

// Before the pub() allow-list landed, GET /api/data served every user's
// resetToken and emailVerifyToken to anonymous callers. Any token that existed
// then must be treated as compromised, so burn them all once. Password reset
// links issued before this deploy will stop working — users simply request a
// new one.
if (!db.meta.tokensPurgedAt) {
  let purged = 0;
  db.users.forEach(u => {
    if (u.resetToken || u.resetTokenExpiry) { u.resetToken = null; u.resetTokenExpiry = null; purged++; }
    // Only unverified accounts still need their verify token; reissue on demand.
    if (u.emailVerifyToken && u.emailVerified) u.emailVerifyToken = null;
  });
  db.meta.tokensPurgedAt = Date.now();
  console.log(`[migration] Invalidated potentially-exposed reset tokens for ${purged} user(s).`);
}

saveDB();

function uid() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}

// idFileName is user-supplied and is rendered in the admin panel. Reduce it to a
// plain filename so it can never carry markup, path separators, or unbounded length.
// Per-address throttle for anything that sends mail. The IP-based limiter keys
// on a spoofable header, so on its own it does not stop someone from bombing one
// person's inbox (and burning Resend quota and sender reputation) by rotating
// X-Forwarded-For. Keyed on the target address, which cannot be rotated.
const _mailSends = new Map();
const MAIL_WINDOW_MS = 15 * 60 * 1000;
const MAIL_MAX_PER_WINDOW = 3;

function mailAllowed(email) {
  const now = Date.now();
  if (_mailSends.size > 10000) {
    for (const [k, v] of _mailSends) if (now - v.first > MAIL_WINDOW_MS) _mailSends.delete(k);
  }
  const rec = _mailSends.get(email);
  if (!rec || now - rec.first > MAIL_WINDOW_MS) {
    _mailSends.set(email, { first: now, count: 1 });
    return true;
  }
  if (rec.count >= MAIL_MAX_PER_WINDOW) return false;
  rec.count++;
  return true;
}

function safeFileName(name) {
  if (typeof name !== 'string') return '';
  return name.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 120);
}

// Profile photos are stored inline as data URIs and rendered into an <img src>.
// Anything that is not a well-formed base64 image is rejected outright: an
// arbitrary string here becomes attribute-injection at every render site.
// The pattern is linear (one character class, one quantifier) so it cannot
// backtrack pathologically on a multi-megabyte input.
const DATA_IMAGE_RE = /^data:image\/(?:png|jpeg|jpg|gif|webp);base64,[A-Za-z0-9+/]+={0,2}$/;

function safeImage(value) {
  if (typeof value !== 'string') return '';
  const s = value.trim();
  return DATA_IMAGE_RE.test(s) ? s : '';
}

// Source URLs are optional and become href attributes. Only http(s) may through —
// a "javascript:" or "data:" URL here would execute for every reader who clicks.
function safeUrl(url) {
  if (typeof url !== 'string' || !url.trim()) return '';
  let trimmed = url.trim().slice(0, 2000);
  // A bare "example.com" is meant as an external link.
  if (!/^[a-z][a-z0-9+.-]*:/i.test(trimmed)) trimmed = 'https://' + trimmed;
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return '';
    return parsed.href;
  } catch(e) { return ''; }
}

// ─── CLIENT IDENTITY ──────────────────────────────────────────────────────────
// Behind Railway's proxy chain req.ip resolves to an internal address that
// varies between requests, which silently defeats anything keyed on it — rate
// limits stop accumulating and view dedupe never matches. The real client is the
// leftmost X-Forwarded-For entry. That value is spoofable, so treat it as a
// best-effort grouping key, never as proof of identity.
function clientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff) {
    const first = xff.split(',')[0].trim();
    if (first) return first;
  }
  return req.ip || 'unknown';
}

// ─── MIDDLEWARE ───────────────────────────────────────────────────────────────

app.use(cors({ origin: ORIGIN }));

// Tight limit on credential endpoints (brute force, reset-token spraying),
// a generous one everywhere else so ordinary browsing — and anyone behind a
// shared NAT — is never locked out.
const limiterBase = {
  windowMs: 15 * 60 * 1000,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: clientIp,
  // keyGenerator returns an already-normalised string, so skip the built-in
  // IPv6 fallback validation rather than letting it warn on every request.
  validate: { keyGeneratorIpFallback: false }
};

const authLimiter = rateLimit({
  ...limiterBase,
  max: 20,
  message: { error: 'Too many attempts. Please try again in a few minutes.' }
});
app.use('/api/auth', authLimiter);
app.use('/api/admin', authLimiter);

app.use(rateLimit({ ...limiterBase, max: 1000 }));

app.use(express.json({ limit: '10mb' }));

// Handlers destructure req.body directly. body-parser only sets req.body when
// the Content-Type actually matches, so a POST with a missing or non-JSON
// Content-Type leaves it undefined — and destructuring undefined inside an
// async handler becomes an unhandled rejection, which exits the process on
// modern Node. One unauthenticated request could take the whole site down.
app.use((req, res, next) => {
  if (req.body === undefined || req.body === null || typeof req.body !== 'object')
    req.body = {};
  next();
});

// NOTE: do NOT serve a directory here. The frontend is hosted on GitHub Pages,
// and an earlier version served path.join(__dirname, '..') — which resolves to
// the filesystem root in the container, exposing data.json and everything else.

// The moderation panel is served from the backend rather than published to
// GitHub Pages, so it is same-origin with the API it calls (no CORS) and no
// longer sits on the public saloon.org domain. This is ONE named file with a
// hardcoded path — it takes nothing from the request, so unlike the
// express.static(root) mistake above there is no path-traversal surface.
// The page is inert without ADMIN_SECRET; requireAdmin remains the real boundary.
app.get('/admin', (req, res) => {
  // helmet's global default sets script-src 'self' and script-src-attr 'none',
  // which would block this page's inline <script> and its inline onclick
  // handlers. Relax it for this one response only.
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "script-src-attr 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline'",
    "connect-src 'self'",
    "img-src 'self' data:",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'"
  ].join('; '));
  res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// Auth middleware — hard-fails with 401.
// A valid signature is NOT sufficient. The token is a 30-day bearer credential
// with no revocation list, so every request must also confirm the account still
// exists and is still allowed to act — otherwise deleting a user leaves them
// posting for up to 30 days, and an unverified signup can write immediately.
function requireAuth(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error: 'Not authenticated.' });
  let claims;
  try {
    claims = jwt.verify(h.slice(7), SECRET, { algorithms: ['HS256'] });
  } catch(e) { return res.status(401).json({ error: 'Session expired. Please sign in again.' }); }

  const user = db.users.find(u => u.id === claims.id);
  if (!user) return res.status(401).json({ error: 'This account no longer exists.' });
  if (!user.emailVerified)
    return res.status(403).json({
      error: 'Please verify your email before continuing. Check your inbox for a verification link.',
      emailVerificationRequired: true
    });

  req.user    = claims;
  req.account = user;
  next();
}

// Auth middleware — passes through without a token (req.user may be undefined).
// A token for a deleted account is treated as anonymous rather than trusted.
function optionalAuth(req, res, next) {
  const h = req.headers.authorization;
  if (h && h.startsWith('Bearer ')) {
    try {
      const claims = jwt.verify(h.slice(7), SECRET, { algorithms: ['HS256'] });
      const user = db.users.find(u => u.id === claims.id);
      if (user) { req.user = claims; req.account = user; }
    } catch(e) {}
  }
  next();
}

// The site owner, resolved from the stored account rather than from anything the
// client sends. The frontend's isAdmin() is a UI affordance only — every
// privileged action must re-check here.
function isSiteAdmin(req) {
  if (!req.user) return false;
  const u = db.users.find(x => x.id === req.user.id);
  return !!u && u.email === ADMIN_EMAIL;
}

// Measured from publication where known, so time spent as an unpublished draft
// doesn't eat into the author's editing window.
function withinEditWindow(item) {
  return Date.now() - (item.publishedAt || item.createdAt || 0) <= EDIT_WINDOW_MS;
}

// Public projection of a user. This is an ALLOW-LIST on purpose: a deny-list
// leaks every field added later, and previously exposed resetToken and
// emailVerifyToken to anonymous callers of /api/data — enough to take over any
// account. Never add a secret-bearing field here.
const PUBLIC_USER_FIELDS = [
  'id', 'firstName', 'lastName', 'verified', 'idSubmitted', 'createdAt',
  'bio', 'credentials', 'interests', 'recommendedBooks', 'recommendedFilms',
  'following', 'photo'
];

function pub(u) {
  const safe = {};
  PUBLIC_USER_FIELDS.forEach(k => { if (u[k] !== undefined) safe[k] = u[k]; });
  return safe;
}

// Same projection plus the fields a user is allowed to see about themselves.
function pubSelf(u) {
  return Object.assign(pub(u), {
    email: u.email,
    emailVerified: u.emailVerified,
    idFileName: u.idFileName,
    isAdmin: u.email === ADMIN_EMAIL
  });
}

// ─── AUTH ─────────────────────────────────────────────────────────────────────

// ─── GOOGLE AUTH ──────────────────────────────────────────────────────────────

async function verifyGoogleToken(credential) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'oauth2.googleapis.com',
      path: `/tokeninfo?id_token=${encodeURIComponent(credential)}`,
      method: 'GET',
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const payload = JSON.parse(data);
          if (payload.error_description) return reject(new Error(payload.error_description));
          // Google will happily validate a token minted for ANY OAuth client.
          // Without this check, an attacker can mint a token in their own app
          // and present it here to sign in as that email.
          if (payload.aud !== GOOGLE_CLIENT_ID)
            return reject(new Error('Token was not issued for this application.'));
          // email_verified comes back as the string "true" from tokeninfo.
          if (payload.email_verified !== 'true' && payload.email_verified !== true)
            return reject(new Error('Google account email is not verified.'));
          if (!payload.email)
            return reject(new Error('Token carries no email address.'));
          resolve(payload);
        } catch(e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

app.post('/api/auth/google', async (req, res) => {
  const { credential } = req.body;
  if (!credential) return res.status(400).json({ error: 'Missing Google credential.' });
  let payload;
  try { payload = await verifyGoogleToken(credential); }
  catch(e) { return res.status(401).json({ error: 'Invalid Google token.' }); }

  const email = (payload.email || '').toLowerCase().trim();
  if (!email) return res.status(400).json({ error: 'No email from Google.' });

  const existing = db.users.find(u => u.email === email);
  if (existing) {
    // Existing user — log them in
    existing.googleId = payload.sub;
    saveDB();
    const token = jwt.sign({ id: existing.id }, SECRET, { expiresIn: '30d' });
    return res.json({ user: pubSelf(existing), token });
  }

  // New user — tell frontend to show registration form
  res.json({ needsRegistration: true, email });
});

app.post('/api/auth/register', async (req, res) => {
  const { firstName, lastName, email, password, googleCredential, idFileName } = req.body;
  if (!firstName || !lastName || !email)
    return res.status(400).json({ error: 'All fields are required.' });
  if (typeof firstName !== 'string' || typeof lastName !== 'string' || typeof email !== 'string')
    return res.status(400).json({ error: 'Invalid field types.' });
  if (!email.includes('@'))
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  if (email.length > 254)
    return res.status(400).json({ error: 'Email address is too long.' });
  if (firstName.trim().length > 60 || lastName.trim().length > 60)
    return res.status(400).json({ error: 'Name is too long (max 60 characters each).' });

  let passwordHash = null;
  let googleId = null;

  if (googleCredential) {
    let payload;
    try { payload = await verifyGoogleToken(googleCredential); }
    catch(e) { return res.status(401).json({ error: 'Invalid Google token.' }); }
    if ((payload.email || '').toLowerCase().trim() !== email.toLowerCase().trim())
      return res.status(400).json({ error: 'Email does not match Google account.' });
    googleId = payload.sub;
  } else {
    if (!password || password.length < 6)
      return res.status(400).json({ error: 'Password must be at least 6 characters.' });
    passwordHash = await bcrypt.hash(password, 10);
  }

  if (db.users.find(u => u.email === email.toLowerCase().trim()))
    return res.status(400).json({ error: 'An account with that email already exists.' });
  const emailVerifyToken = googleId ? null : crypto.randomBytes(32).toString('hex');
  const user = {
    id: uid(),
    firstName: firstName.trim(),
    lastName: lastName.trim(),
    email: email.toLowerCase().trim(),
    passwordHash,
    googleId: googleId || null,
    emailVerified: !!googleId,
    emailVerifyToken,
    emailVerifyTokenExpiry: emailVerifyToken ? Date.now() + EMAIL_VERIFY_TTL_MS : null,
    idFileName: safeFileName(idFileName),
    idSubmitted: !!idFileName,
    verified: false,
    createdAt: Date.now(),
    bio: '', credentials: [], interests: [],
    recommendedBooks: [], recommendedFilms: [], following: []
  };

  const pending = db.invitations.filter(i => i.email === user.email);
  pending.forEach(inv => {
    const c = db.conversations.find(c => c.id === inv.convId);
    if (c && !c.participants.includes(user.id)) c.participants.push(user.id);
  });
  db.invitations = db.invitations.filter(i => i.email !== user.email);

  db.users.push(user);
  saveDB();

  if (!googleId) {
    const verifyUrl = `${SITE_URL}?verify=${emailVerifyToken}`;
    await sendMail(user.email, 'Verify your Saloon email', `
      <p>Hi ${user.firstName},</p>
      <p>Click the link below to verify your email address and activate your Saloon account:</p>
      <p><a href="${verifyUrl}">${verifyUrl}</a></p>
      <p>This link expires in 24 hours.</p>
    `).catch(e => console.error('[email] send failed:', e.message));
  }

  const token = jwt.sign({ id: user.id }, SECRET, { expiresIn: '30d' });
  res.json({ user: pubSelf(user), token, emailVerificationRequired: !googleId });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.users.find(u => u.email === email?.toLowerCase()?.trim());
  // One generic message for every failure mode — "no such account", "wrong
  // password", and "that's a Google account" each turn this endpoint into an
  // account-enumeration oracle if they answer differently. The hint about Google
  // is shown to everyone, so it guides real users without confirming anything.
  const GENERIC = 'Incorrect email or password. If you signed up with Google, use "Continue with Google" instead.';
  if (!user) {
    // Spend comparable time so response latency doesn't leak existence either.
    try { await bcrypt.hash(String(password || ''), 10); } catch(e) {}
    return res.status(400).json({ error: GENERIC });
  }
  if (!user.passwordHash) {
    try { await bcrypt.hash(String(password || ''), 10); } catch(e) {}
    return res.status(400).json({ error: GENERIC });
  }
  const ok = await bcrypt.compare(password || '', user.passwordHash);
  if (!ok) return res.status(400).json({ error: GENERIC });
  if (!user.emailVerified)
    return res.status(403).json({ error: 'Please verify your email before signing in. Check your inbox for a verification link.', emailVerificationRequired: true });
  const token = jwt.sign({ id: user.id }, SECRET, { expiresIn: '30d' });
  res.json({ user: pubSelf(user), token });
});

app.post('/api/auth/verify-email', (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'Token is required.' });
  const user = db.users.find(u => u.emailVerifyToken === token);
  // The email promises this link expires in 24 hours, and it must actually do
  // so — otherwise an old message recovered years later still mints a session.
  if (!user || !user.emailVerifyTokenExpiry || user.emailVerifyTokenExpiry < Date.now())
    return res.status(400).json({ error: 'Invalid or expired verification link.' });
  user.emailVerified = true;
  user.emailVerifyToken = null;
  user.emailVerifyTokenExpiry = null;
  saveDB();
  const jwt_token = jwt.sign({ id: user.id }, SECRET, { expiresIn: '30d' });
  res.json({ user: pubSelf(user), token: jwt_token });
});

app.post('/api/auth/resend-verification', async (req, res) => {
  const { email } = req.body;
  const user = db.users.find(u => u.email === email?.toLowerCase()?.trim());
  if (!user || user.emailVerified) return res.json({ ok: true }); // silent — don't leak info
  if (!mailAllowed(user.email)) return res.json({ ok: true });     // silent throttle
  const newToken = crypto.randomBytes(32).toString('hex');
  user.emailVerifyToken = newToken;
  user.emailVerifyTokenExpiry = Date.now() + EMAIL_VERIFY_TTL_MS;
  saveDB();
  const verifyUrl = `${SITE_URL}?verify=${newToken}`;
  await sendMail(user.email, 'Verify your Saloon email', `
    <p>Hi ${user.firstName},</p>
    <p>Click the link below to verify your email address:</p>
    <p><a href="${verifyUrl}">${verifyUrl}</a></p>
  `).catch(e => console.error('[email] send failed:', e.message));
  res.json({ ok: true });
});

app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  const user = db.users.find(u => u.email === email?.toLowerCase()?.trim());
  res.json({ ok: true }); // always respond ok — don't leak whether email exists
  if (!user) return;
  if (!mailAllowed(user.email)) return; // silent throttle — don't bomb an inbox
  const resetToken = crypto.randomBytes(32).toString('hex');
  user.resetToken = resetToken;
  user.resetTokenExpiry = Date.now() + 60 * 60 * 1000; // 1 hour
  saveDB();
  const resetUrl = `${SITE_URL}?reset=${resetToken}`;
  await sendMail(user.email, 'Reset your Saloon password', `
    <p>Hi ${user.firstName},</p>
    <p>Click the link below to reset your password. This link expires in 1 hour.</p>
    <p><a href="${resetUrl}">${resetUrl}</a></p>
    <p>If you didn't request this, you can safely ignore this email.</p>
  `).catch(e => console.error('[email] send failed:', e.message));
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json({ error: 'Token and password are required.' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  const user = db.users.find(u => u.resetToken === token && u.resetTokenExpiry > Date.now());
  if (!user) return res.status(400).json({ error: 'Reset link is invalid or has expired.' });
  user.passwordHash = await bcrypt.hash(password, 10);
  user.resetToken = null;
  user.resetTokenExpiry = null;
  user.emailVerified = true; // password reset implies email ownership
  saveDB();
  const jwt_token = jwt.sign({ id: user.id }, SECRET, { expiresIn: '30d' });
  res.json({ user: pubSelf(user), token: jwt_token });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  res.json(pubSelf(user));
});

// ─── DATA SNAPSHOT ────────────────────────────────────────────────────────────
// Returns everything the frontend needs to hydrate its local DB.
// Password hashes are never included.

app.get('/api/data', optionalAuth, (req, res) => {
  const userId = req.user?.id;
  res.json({
    users:         db.users.map(pub),
    conversations: db.conversations.filter(c => !c.draft || c.creatorId === userId),
    posts:         db.posts.filter(p => !p.draft || p.authorId === userId),
    // Comments quote the text they annotate, so an unfiltered list hands out
    // excerpts of unpublished drafts even though the draft itself is hidden.
    comments: db.comments.filter(c => {
      const conv = db.conversations.find(x => x.id === c.conversationId);
      if (!conv) return false;
      if (conv.draft && conv.creatorId !== userId) return false;
      if (!c.postId) return true;
      const post = db.posts.find(p => p.id === c.postId);
      if (!post) return false;
      return !post.draft || post.authorId === userId;
    }),
    // Invitations carry email addresses of people who may not even have an
    // account — only show them to participants of the conversation involved.
    invitations:   userId
      ? db.invitations.filter(i => {
          const c = db.conversations.find(c => c.id === i.convId);
          return c && (c.participants || []).includes(userId);
        })
      : []
  });
});

// ─── CONVERSATIONS ────────────────────────────────────────────────────────────

app.post('/api/conversations', requireAuth, (req, res) => {
  const { title, category, content, draft } = req.body;
  if (!title || !category || !content)
    return res.status(400).json({ error: 'title, category, and content are required.' });
  // These MUST be type-checked before .length. On a non-string, .length is
  // either undefined (so `> 20000` is false) or an array's element count, and
  // either way a multi-megabyte payload slips past the cap and is then served
  // to every visitor by /api/data.
  if (typeof title !== 'string' || typeof category !== 'string' || typeof content !== 'string')
    return res.status(400).json({ error: 'title, category, and content must be text.' });
  if (title.length > 200)     return res.status(400).json({ error: 'Title too long (max 200 chars).' });
  if (category.length > 60)   return res.status(400).json({ error: 'Category too long (max 60 chars).' });
  if (content.length > 20000) return res.status(400).json({ error: 'Content too long (max 20 000 chars).' });

  const conv = {
    id: uid(), title, category,
    creatorId: req.user.id,
    participants: [req.user.id],
    createdAt: Date.now(), lastActivity: Date.now(),
    viewCount: 0, likes: [], dislikes: [],
    draft: !!draft
  };
  const post = {
    id: uid(), conversationId: conv.id,
    authorId: req.user.id, content, draft: !!draft, createdAt: Date.now()
  };
  db.conversations.push(conv);
  db.posts.push(post);
  saveDB();
  res.json({ conversation: conv, post });
});

app.patch('/api/conversations/:id', requireAuth, (req, res) => {
  const conv = db.conversations.find(c => c.id === req.params.id);
  if (!conv) return res.status(404).json({ error: 'Conversation not found.' });
  if (conv.creatorId !== req.user.id && !isSiteAdmin(req))
    return res.status(403).json({ error: 'Only the creator can edit this.' });
  if (req.body.title)    conv.title    = String(req.body.title).slice(0, 200);
  if (req.body.category) conv.category = String(req.body.category).slice(0, 60);
  saveDB();
  res.json(conv);
});


app.put('/api/conversations/:id', requireAuth, (req, res) => {
  const conv = db.conversations.find(c => c.id === req.params.id);
  if (!conv) return res.status(404).json({ error: 'Conversation not found.' });
  const isCreator = conv.creatorId === req.user.id;

  // Any authenticated user can submit a join request for themselves. The stored
  // record is rebuilt from scratch — accepting the client's object verbatim let
  // a caller stash arbitrary fields on the conversation.
  if (req.body.joinRequests !== undefined && !isCreator) {
    const incoming  = Array.isArray(req.body.joinRequests) ? req.body.joinRequests : [];
    const existing  = conv.joinRequests || [];
    const mine      = incoming.find(r => r && r.userId === req.user.id);
    if (conv.participants.includes(req.user.id))
      return res.status(400).json({ error: 'You are already a participant.' });
    if (mine && !existing.some(r => r.userId === req.user.id)) {
      existing.push({
        userId:      req.user.id,
        message:     String(mine.message || '').slice(0, 1000),
        requestedAt: Date.now()
      });
    }
    conv.joinRequests = existing;
    saveDB();
    return res.json(conv);
  }

  if (!isCreator && !isSiteAdmin(req))
    return res.status(403).json({ error: 'Only the creator can edit this.' });
  if (req.body.title !== undefined) conv.title = String(req.body.title).slice(0, 200);
  if (req.body.draft !== undefined) {
    conv.draft = !!req.body.draft;
    if (!conv.draft) conv.lastActivity = Date.now();
  }
  if (req.body.joinRequests !== undefined) {
    const list = Array.isArray(req.body.joinRequests) ? req.body.joinRequests : [];
    conv.joinRequests = list
      .filter(r => r && db.users.some(u => u.id === r.userId))
      .map(r => ({
        userId:      r.userId,
        message:     String(r.message || '').slice(0, 1000),
        requestedAt: Number(r.requestedAt) || Date.now()
      }));
  }
  if (req.body.participants !== undefined && Array.isArray(req.body.participants)) {
    // Only real user IDs, no duplicates, and the creator can never be removed.
    const next = req.body.participants.filter(id => db.users.some(u => u.id === id));
    if (!next.includes(conv.creatorId)) next.push(conv.creatorId);
    conv.participants = [...new Set(next)];
  }
  saveDB();
  res.json(conv);
});

app.delete('/api/conversations/:id', requireAuth, (req, res) => {
  const idx = db.conversations.findIndex(c => c.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Conversation not found.' });
  if (db.conversations[idx].creatorId !== req.user.id && !isSiteAdmin(req))
    return res.status(403).json({ error: 'Only the creator can delete this.' });
  db.conversations.splice(idx, 1);
  db.posts    = db.posts.filter(p => p.conversationId !== req.params.id);
  db.comments = db.comments.filter(c => c.conversationId !== req.params.id);
  saveDB();
  res.json({ ok: true });
});

// In-memory dedupe so one visitor can't inflate a count by replaying the request.
// Cleared on restart, which is fine — it only needs to blunt trivial abuse.
const _recentViews = new Map();
const VIEW_DEDUPE_MS = 60 * 60 * 1000;

app.post('/api/conversations/:id/view', optionalAuth, (req, res) => {
  const conv = db.conversations.find(c => c.id === req.params.id);
  if (!conv) return res.status(404).json({ error: 'Not found.' });

  const who = req.user?.id || clientIp(req);
  const key = `${who}:${conv.id}`;
  const now = Date.now();

  if (_recentViews.size > 20000) {
    for (const [k, t] of _recentViews) if (now - t > VIEW_DEDUPE_MS) _recentViews.delete(k);
  }

  const last = _recentViews.get(key);
  if (last && now - last < VIEW_DEDUPE_MS)
    return res.json({ viewCount: conv.viewCount || 0 });

  _recentViews.set(key, now);
  conv.viewCount = (conv.viewCount || 0) + 1;
  saveDB();
  res.json({ viewCount: conv.viewCount });
});

app.post('/api/conversations/:id/vote', requireAuth, (req, res) => {
  const conv = db.conversations.find(c => c.id === req.params.id);
  if (!conv) return res.status(404).json({ error: 'Not found.' });
  const userId = req.user.id;
  const { type } = req.body;
  // Anything that wasn't the string 'like' used to fall through to dislike, so
  // a malformed request silently registered the opposite of nothing.
  if (type !== 'like' && type !== 'dislike')
    return res.status(400).json({ error: "type must be 'like' or 'dislike'." });
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
  const { conversationId, content, draft } = req.body;
  if (!content || typeof content !== 'string' || content.length > 20000)
    return res.status(400).json({ error: 'Content required and must be under 20 000 chars.' });
  const conv = db.conversations.find(c => c.id === conversationId);
  if (!conv) return res.status(404).json({ error: 'Conversation not found.' });
  if (!conv.participants.includes(req.user.id))
    return res.status(403).json({ error: 'You are not a participant in this conversation.' });
  const post = { id: uid(), conversationId, authorId: req.user.id, content, draft: !!draft, createdAt: Date.now() };
  db.posts.push(post);
  if (!draft) conv.lastActivity = Date.now();
  saveDB();
  res.json(post);
});

app.put('/api/posts/:id', requireAuth, (req, res) => {
  const post = db.posts.find(p => p.id === req.params.id);
  if (!post) return res.status(404).json({ error: 'Post not found.' });
  const admin   = isSiteAdmin(req);
  const isOwner = post.authorId === req.user.id;
  if (!isOwner && !admin) return res.status(403).json({ error: 'Not your post.' });

  const { content, draft, sources } = req.body;

  // Un-publishing must be rejected BEFORE anything else. Without this, the edit
  // window is trivially bypassed: PUT {draft:true} is unchecked, and the content
  // guard below short-circuits on !post.draft, so a two-request sequence lets an
  // author silently rewrite or delete a post of any age.
  if (draft !== undefined && !!draft && !post.draft && !admin)
    return res.status(403).json({ error: 'A published post cannot be returned to draft.' });

  if (content !== undefined) {
    if (typeof content !== 'string' || !content || content.length > 20000)
      return res.status(400).json({ error: 'Invalid content.' });
    // Drafts are unpublished, so the window only applies once a post is live.
    if (!admin && !post.draft && !withinEditWindow(post))
      return res.status(403).json({ error: 'The 24-hour edit window for this post has passed.' });
    if (content !== post.content) {
      // History is recorded here, not accepted from the client — otherwise an
      // author could rewrite a post and forge the trail that proves they did.
      post.edits = (post.edits || []).concat({ content: post.content, editedAt: Date.now() }).slice(-100);
      post.content = content;
    }
  }

  if (draft !== undefined) {
    const nowPublished = post.draft && !draft;
    post.draft = !!draft;
    // The window runs from publication, not creation, so a post that sat as a
    // draft for a week still gets its full 24 hours once it goes live.
    if (nowPublished) post.publishedAt = Date.now();
  }

  // Sources may be revised at any time, by design.
  if (sources !== undefined) {
    if (!Array.isArray(sources)) return res.status(400).json({ error: 'Invalid sources.' });
    post.sources = sources.slice(0, 20).map(s => ({
      label: String(s && s.label || '').slice(0, 300),
      url:   safeUrl(s && s.url)
    })).filter(s => s.label);
  }
  if (!post.draft) {
    const conv = db.conversations.find(c => c.id === post.conversationId);
    if (conv) conv.lastActivity = Date.now();
  }
  saveDB();
  res.json(post);
});

app.delete('/api/posts/:id', requireAuth, (req, res) => {
  const idx = db.posts.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Post not found.' });
  const post = db.posts[idx];
  const admin = isSiteAdmin(req);
  if (post.authorId !== req.user.id && !admin)
    return res.status(403).json({ error: 'Not your post.' });
  if (!admin && !post.draft && !withinEditWindow(post))
    return res.status(403).json({ error: 'The 24-hour window for deleting this post has passed.' });
  db.posts.splice(idx, 1);
  db.comments = db.comments.filter(c => c.postId !== post.id);
  saveDB();
  res.json({ ok: true });
});

// ─── COMMENTS ─────────────────────────────────────────────────────────────────

app.post('/api/comments', requireAuth, (req, res) => {
  const { conversationId, postId, selectedText, content } = req.body;
  if (!conversationId || !content)
    return res.status(400).json({ error: 'conversationId and content are required.' });
  if (typeof content !== 'string' || content.length > 5000)
    return res.status(400).json({ error: 'Comment too long (max 5 000 chars).' });
  if (!db.conversations.some(c => c.id === conversationId))
    return res.status(404).json({ error: 'Conversation not found.' });
  if (postId && !db.posts.some(p => p.id === postId && p.conversationId === conversationId))
    return res.status(400).json({ error: 'That post is not part of this conversation.' });
  const comment = {
    id: uid(), conversationId,
    postId:       postId       || null,
    authorId:     req.user.id,
    selectedText: selectedText ? String(selectedText).slice(0, 2000) : null,
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
  const b = req.body;

  if (b.bio !== undefined) {
    if (typeof b.bio !== 'string') return res.status(400).json({ error: 'Bio must be text.' });
    if (b.bio.length > 1000)       return res.status(400).json({ error: 'Bio too long (max 1 000 chars).' });
    user.bio = b.bio;
  }

  if (b.photo !== undefined) {
    // The size check used to apply only when photo was a string, so sending it
    // as an object skipped the cap entirely. It is also rendered into an
    // <img src>, so anything that isn't a real data-URI image is rejected.
    if (b.photo === null || b.photo === '') {
      user.photo = '';
    } else {
      if (typeof b.photo !== 'string')
        return res.status(400).json({ error: 'Photo must be an image data URL.' });
      if (b.photo.length > 5 * 1024 * 1024)
        return res.status(400).json({ error: 'Photo too large (max 5 MB).' });
      const img = safeImage(b.photo);
      if (!img) return res.status(400).json({ error: 'Photo must be a PNG, JPEG, GIF, or WebP image.' });
      user.photo = img;
    }
  }

  // These render as lists on the profile. Without a type check a client can
  // store a string or object here and every visitor's profile render throws.
  const LIST_FIELDS = { credentials: 40, interests: 40, recommendedBooks: 100, recommendedFilms: 100 };
  for (const [field, maxLen] of Object.entries(LIST_FIELDS)) {
    if (b[field] === undefined) continue;
    if (!Array.isArray(b[field]))
      return res.status(400).json({ error: `${field} must be a list.` });
    if (b[field].length > 50)
      return res.status(400).json({ error: `Too many entries in ${field} (max 50).` });
    user[field] = b[field].slice(0, 50).map(item => {
      // Books and films are {title, author} objects; the rest are plain strings.
      if (item && typeof item === 'object' && !Array.isArray(item)) {
        return {
          title:  String(item.title  || '').slice(0, maxLen),
          author: String(item.author || '').slice(0, maxLen)
        };
      }
      return String(item == null ? '' : item).slice(0, maxLen);
    });
  }

  saveDB();
  res.json(pubSelf(user));
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

// ─── ADMIN ────────────────────────────────────────────────────────────────────
// Protected by a separate ADMIN_SECRET env var — never the same as JWT_SECRET.
// Both are declared and validated at the top of this file.

function requireAdmin(req, res, next) {
  const key = req.headers['x-admin-key'];
  if (typeof key !== 'string') return res.status(401).json({ error: 'Unauthorized.' });
  const a = Buffer.from(key), b = Buffer.from(ADMIN_SECRET);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b))
    return res.status(401).json({ error: 'Unauthorized.' });
  next();
}

// The moderation view of a user. Carries an email address and an ID-document
// filename, so it must only ever reach the site owner — never /api/data, and
// never the client's cached copy of the database.
function moderationView(u) {
  return {
    id: u.id,
    firstName: u.firstName,
    lastName: u.lastName,
    email: u.email,
    verified: u.verified,
    idSubmitted: u.idSubmitted,
    idRejected: !!u.idRejected,
    idFileName: u.idFileName,
    emailVerified: !!u.emailVerified,
    createdAt: u.createdAt
  };
}

app.get('/api/admin/users', requireAdmin, (req, res) => {
  res.json(db.users.map(moderationView));
});

// ─── MODERATION (signed-in owner) ─────────────────────────────────────────────
// The same review tasks as the standalone panel, authorised by the owner's own
// session instead of the shared secret, so they can be done from the live site.
//
// Deliberately NOT mounted under /api/admin: that prefix carries a 20-per-15-min
// limiter sized for guessing attacks against the shared secret, which would
// throttle an owner working through a queue of signups. These routes are behind
// a real session, so the general limiter is the right one.
//
// Irreversible actions are NOT here. Deleting a user and wiping all content
// still require the shared secret, so that a stolen session token — the JWT
// lives in localStorage and the app cannot rule out XSS — cannot destroy data.
function requireSiteAdmin(req, res, next) {
  if (!isSiteAdmin(req)) return res.status(403).json({ error: 'Not authorised.' });
  next();
}

app.get('/api/moderation/users', requireAuth, requireSiteAdmin, (req, res) => {
  res.json(db.users.map(moderationView));
});

app.patch('/api/moderation/users/:id/verify', requireAuth, requireSiteAdmin, (req, res) => {
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  user.verified = true;
  user.idRejected = false;
  saveDB();
  console.log(`[moderation] ${req.account.email} verified ${user.id}`);
  res.json(moderationView(user));
});

app.patch('/api/moderation/users/:id/reject', requireAuth, requireSiteAdmin, (req, res) => {
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  user.verified = false;
  user.idSubmitted = false;
  user.idRejected = true;
  saveDB();
  console.log(`[moderation] ${req.account.email} rejected ${user.id}`);
  res.json(moderationView(user));
});

// ─── STEP-UP FOR IRREVERSIBLE ACTIONS ─────────────────────────────────────────
// Deleting an account cascades and cannot be undone. Gating it on the session
// alone would mean a single stored-XSS bug — two were found in this codebase
// this week — could delete every user, because the session token sits in
// localStorage where injected script can read it. So it additionally requires
// proof the operator just typed the shared secret, which is never persisted
// anywhere the page can reach.
//
// The window covers a batch of deletions rather than one, so working through a
// queue does not mean retyping the secret repeatedly and looking for a way round
// it. Signed with a key derived from ADMIN_SECRET, so it is distinct from both
// ADMIN_SECRET and JWT_SECRET and needs no extra configuration.
const STEPUP_SECRET = crypto.createHmac('sha256', ADMIN_SECRET).update('saloon-stepup-v1').digest('hex');
const STEPUP_TTL = '5m';

app.post('/api/moderation/elevate', requireAuth, requireSiteAdmin, (req, res) => {
  const key = req.body.adminKey;
  if (typeof key !== 'string') return res.status(400).json({ error: 'Admin key is required.' });
  const a = Buffer.from(key), b = Buffer.from(ADMIN_SECRET);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    console.warn(`[moderation] failed elevation attempt by ${req.account.email}`);
    return res.status(401).json({ error: 'That admin key is not correct.' });
  }
  const token = jwt.sign({ sub: req.user.id, purpose: 'moderation-stepup' }, STEPUP_SECRET, { expiresIn: STEPUP_TTL });
  console.log(`[moderation] ${req.account.email} elevated`);
  res.json({ token, expiresIn: 300 });
});

function requireStepUp(req, res, next) {
  const raw = req.headers['x-step-up'];
  if (typeof raw !== 'string' || !raw)
    return res.status(401).json({ error: 'This action needs the admin key.', stepUpRequired: true });
  try {
    const claims = jwt.verify(raw, STEPUP_SECRET, { algorithms: ['HS256'] });
    // Bound to the operator who elevated, so a token cannot be reused by another
    // session even if it leaks.
    if (claims.purpose !== 'moderation-stepup' || claims.sub !== req.user.id)
      return res.status(401).json({ error: 'This action needs the admin key.', stepUpRequired: true });
  } catch (e) {
    return res.status(401).json({ error: 'Your admin key confirmation expired.', stepUpRequired: true });
  }
  next();
}

app.delete('/api/moderation/users/:id', requireAuth, requireSiteAdmin, requireStepUp, (req, res) => {
  if (req.params.id === req.user.id)
    return res.status(400).json({ error: 'You cannot delete your own account here.' });
  const result = deleteUserCascade(req.params.id);
  if (!result) return res.status(404).json({ error: 'User not found.' });
  console.log(`[moderation] ${req.account.email} DELETED user ${req.params.id}`);
  res.json({ ok: true });
});

app.patch('/api/admin/users/:id/verify', requireAdmin, (req, res) => {
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  user.verified = true;
  saveDB();
  res.json({ ok: true });
});

app.patch('/api/admin/users/:id/reject', requireAdmin, (req, res) => {
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  user.verified = false;
  user.idSubmitted = false;
  user.idRejected = true;
  saveDB();
  res.json({ ok: true });
});

// Shared by both delete paths so they can never drift apart. Returns false if
// there is no such user.
//
// Cascade, or the account's content stays behind pointing at an id that no
// longer resolves: authorless posts, a conversation whose creator can never be
// matched again (so nobody but an admin can ever edit it), and follower lists
// naming a ghost.
function deleteUserCascade(id) {
  const idx = db.users.findIndex(u => u.id === id);
  if (idx === -1) return false;

  const convIds = db.conversations.filter(c => c.creatorId === id).map(c => c.id);
  db.conversations = db.conversations.filter(c => c.creatorId !== id);
  db.posts    = db.posts.filter(p => p.authorId !== id && !convIds.includes(p.conversationId));
  db.comments = db.comments.filter(c => c.authorId !== id && !convIds.includes(c.conversationId));
  db.invitations = db.invitations.filter(i => i.invitedBy !== id);
  db.conversations.forEach(c => {
    c.participants = (c.participants || []).filter(p => p !== id);
    c.joinRequests = (c.joinRequests || []).filter(r => r.userId !== id);
    c.likes        = (c.likes || []).filter(x => x !== id);
    c.dislikes     = (c.dislikes || []).filter(x => x !== id);
  });
  db.users.forEach(u => { u.following = (u.following || []).filter(f => f !== id); });

  db.users.splice(idx, 1);
  saveDB();
  return true;
}

app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  if (!deleteUserCascade(req.params.id))
    return res.status(404).json({ error: 'User not found.' });
  res.json({ ok: true });
});

app.delete('/api/admin/reset-content', requireAdmin, (req, res) => {
  db.conversations = [];
  db.posts = [];
  db.comments = [];
  saveDB();
  res.json({ ok: true, message: 'All conversations, posts, and comments deleted.' });
});

// ─── ERROR HANDLING ───────────────────────────────────────────────────────────

// 404 for unmatched API routes, so they return JSON rather than Express's HTML.
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found.' }));

// Express needs all four parameters to recognise this as an error handler.
// Without it, a thrown error falls through to the default handler and leaks a
// stack trace to the client.
app.use((err, req, res, next) => {
  if (err && (err.type === 'entity.too.large'))
    return res.status(413).json({ error: 'That upload is too large.' });
  if (err && (err.type === 'entity.parse.failed' || err instanceof SyntaxError))
    return res.status(400).json({ error: 'Malformed request body.' });
  console.error('[unhandled]', req.method, req.path, err && err.stack || err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'Something went wrong.' });
});

// ─── SHUTDOWN & LAST-RESORT GUARDS ────────────────────────────────────────────

// Writes are debounced by up to 2s. Railway sends SIGTERM on every redeploy, and
// Node's default action is to exit immediately — killing pending timers and
// silently dropping any mutation whose flush had not fired yet, even though the
// client already received a 200. Flush synchronously on the way out.
let _shuttingDown = false;
function flushSync(reason) {
  if (_shuttingDown) return;
  _shuttingDown = true;
  try {
    clearTimeout(_saveTimer);
    const tmp = DATA + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
    fs.renameSync(tmp, DATA);
    console.log(`[shutdown] Flushed data on ${reason}.`);
  } catch (e) {
    console.error(`[shutdown] Failed to flush on ${reason}:`, e.message);
  }
}

['SIGTERM', 'SIGINT'].forEach(sig => {
  process.on(sig, () => { flushSync(sig); process.exit(0); });
});

// A single unhandled rejection would otherwise take the whole site down. Log it,
// persist what we have, and keep serving rather than dropping every live user.
process.on('unhandledRejection', err => {
  console.error('[unhandledRejection]', err && err.stack || err);
});
process.on('uncaughtException', err => {
  console.error('[uncaughtException]', err && err.stack || err);
  flushSync('uncaughtException');
  process.exit(1);
});

// ─── START ────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log('');
  console.log('  🍺  Saloon backend running at http://localhost:' + PORT);
  console.log('');
  console.log('  To connect the frontend, open commons.html and set:');
  console.log('    const BACKEND_URL = \'http://localhost:' + PORT + '\';');
  console.log('');
  console.log('  JWT_SECRET set:', SECRET !== 'saloon-dev-secret-change-in-production');
  console.log('  RESEND_API_KEY set:', !!RESEND_KEY);
  console.log('  FROM_EMAIL:', FROM_EMAIL);
  console.log('');
});
