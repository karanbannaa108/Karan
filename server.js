// server.js
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const path = require('path');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const fetch = (...args) => import('node-fetch').then(m => m.default(...args));

const app = express();
const PORT = process.env.PORT || 3000;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';
const SESSION_SECRET = process.env.SESSION_SECRET || 'change_this';
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error('Missing DATABASE_URL env var. Set it to your Postgres connection string.');
  // don't exit so dev can still test, but warn
}

// Postgres pool
const pool = new Pool({
  connectionString: DATABASE_URL,
  // In production you might need ssl: { rejectUnauthorized: false } depending on provider
});

// DB init: create users table (karanzero_users). Sessions table for connect-pg-simple is created automatically by the library when needed.
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS karanzero_users (
      id TEXT PRIMARY KEY,
      name TEXT UNIQUE,
      password_hash TEXT,
      role TEXT,
      discord_id TEXT UNIQUE,
      created_at BIGINT
    );
  `);
}
initDb().catch(err => {
  console.error('DB init error', err);
});

// Middlewares
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(cors({
  origin: FRONTEND_URL,
  credentials: true
}));

// Session store using Postgres (table name will be karanzero_sessions)
app.use(session({
  store: new PgSession({
    pool: pool,
    tableName: 'karanzero_sessions' // prefix as requested
  }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: (process.env.NODE_ENV === 'production'),
    httpOnly: true,
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge: 1000 * 60 * 60 * 24 // 1 day
  }
}));

// Rate limiter for auth endpoints
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 8
});

// Helpers
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });
  next();
}
async function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const { rows } = await pool.query('SELECT role FROM karanzero_users WHERE id=$1', [req.session.userId]);
    if (!rows[0] || rows[0].role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    next();
  } catch (e) {
    next(e);
  }
}

// Routes

// Basic register endpoint (optional)
app.post('/auth/register', authLimiter, async (req, res) => {
  const { name, password } = req.body;
  if (!name || !password) return res.status(400).json({ error: 'Missing fields' });
  const id = 'kz_' + uuidv4();
  const hash = await bcrypt.hash(password, 12);
  try {
    await pool.query('INSERT INTO karanzero_users(id,name,password_hash,role,created_at) VALUES($1,$2,$3,$4,$5)', [id, name, hash, 'Member', Date.now()]);
    res.json({ ok: true });
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'User exists' });
    console.error(err); res.status(500).json({ error: 'DB error' });
  }
});

// Login
app.post('/auth/login', authLimiter, async (req, res) => {
  const { name, password } = req.body;
  if (!name || !password) return res.status(400).json({ error: 'Missing fields' });
  try {
    const { rows } = await pool.query('SELECT id, password_hash, role FROM karanzero_users WHERE name=$1', [name]);
    const user = rows[0];
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(400).json({ error: 'Invalid credentials' });
    req.session.userId = user.id;
    res.json({ success: true, role: user.role });
  } catch (e) {
    console.error(e); res.status(500).json({ error: 'Server error' });
  }
});

// Logout
app.post('/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid', { path: '/' });
    res.json({ ok: true });
  });
});

// Discord OAuth (manual flow)
// Step 1: redirect user to Discord authorize page
app.get('/auth/discord', (req, res) => {
  const clientId = process.env.DISCORD_CLIENT_ID;
  const redirect = process.env.DISCORD_REDIRECT;
  if (!clientId || !redirect) return res.status(500).send('Discord not configured');
  const url = `https://discord.com/api/oauth2/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirect)}&response_type=code&scope=identify`;
  res.redirect(url);
});

// Step 2: callback - exchange code for token and fetch user
app.get('/auth/discord/callback', async (req, res) => {
  const code = req.query.code;
  const clientId = process.env.DISCORD_CLIENT_ID;
  const clientSecret = process.env.DISCORD_CLIENT_SECRET;
  const redirect = process.env.DISCORD_REDIRECT;
  if (!code || !clientId || !clientSecret || !redirect) return res.redirect('/login.html');

  try {
    const params = new URLSearchParams();
    params.append('client_id', clientId);
    params.append('client_secret', clientSecret);
    params.append('grant_type', 'authorization_code');
    params.append('code', code);
    params.append('redirect_uri', redirect);

    const tokenResp = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      body: params,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    const tokenJson = await tokenResp.json();
    if (!tokenJson.access_token) return res.redirect('/login.html');

    const userResp = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenJson.access_token}` }
    });
    const discordUser = await userResp.json();

    // create or find user
    const { id: dId, username } = discordUser;
    const { rows } = await pool.query('SELECT * FROM karanzero_users WHERE discord_id=$1', [dId]);
    if (rows[0]) {
      req.session.userId = rows[0].id;
      // if user is admin, redirect to admin, else home
      return res.redirect(rows[0].role === 'admin' ? '/admin.html' : '/');
    } else {
      const newId = 'kz_' + uuidv4();
      await pool.query('INSERT INTO karanzero_users(id,name,role,discord_id,created_at) VALUES($1,$2,$3,$4,$5)', [newId, username, 'Member', dId, Date.now()]);
      req.session.userId = newId;
      return res.redirect('/');
    }
  } catch (err) {
    console.error('Discord callback error', err);
    return res.redirect('/login.html');
  }
});

// Admin-only data
app.get('/admin-data', requireAuth, async (req, res, next) => {
  try {
    const { rows } = await pool.query('SELECT role FROM karanzero_users WHERE id=$1', [req.session.userId]);
    if (!rows[0] || rows[0].role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    const users = (await pool.query('SELECT id, name, role, discord_id, created_at FROM karanzero_users ORDER BY created_at DESC')).rows;
    res.json({ secret: 'KaranZeroDay — Admin data', users });
  } catch (e) { next(e); }
});

// Me
app.get('/me', async (req, res) => {
  if (!req.session.userId) return res.json(null);
  const { rows } = await pool.query('SELECT id, name, role, discord_id FROM karanzero_users WHERE id=$1', [req.session.userId]);
  res.json(rows[0] || null);
});

// Static files (frontend)
app.use(express.static(path.join(__dirname, 'public')));

// Error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Server error' });
});

// Start
app.listen(PORT, () => console.log(`KaranZeroDay backend listening on ${PORT}`));
