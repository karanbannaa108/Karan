// server.js
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');

const app = express();
const DB_FILE = path.join(__dirname, 'database.sqlite');
const db = new sqlite3.Database(DB_FILE);

// Config from env
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'change_me';
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const FRONTEND_URL = process.env.FRONTEND_URL || BASE_URL;
const NODE_ENV = process.env.NODE_ENV || 'development';

// --- Basic security & middlewares ---
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// CORS: allow frontend origin and allow credentials
app.use(cors({
  origin: FRONTEND_URL,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  credentials: true
}));

// Rate limiter for auth endpoints
const authLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 8,
  message: { error: 'Too many requests, slow down.' }
});

// Session
app.use(session({
  genid: () => uuidv4(),
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: '.' }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: NODE_ENV === 'production', // requires HTTPS in production
    sameSite: NODE_ENV === 'production' ? 'none' : 'lax', // 'none' needed for cross-site cookies
    maxAge: 1000 * 60 * 60 * 24 // 1 day
  }
}));

// Passport + Discord OAuth
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
  db.get('SELECT id, name, role, discord_id FROM users WHERE id = ?', [id], (err, row) => {
    if (err) return done(err);
    done(null, row || null);
  });
});

// Discord Strategy (only active if env set)
if (process.env.DISCORD_CLIENT_ID && process.env.DISCORD_CLIENT_SECRET && process.env.DISCORD_CALLBACK_URL) {
  passport.use(new DiscordStrategy({
    clientID: process.env.DISCORD_CLIENT_ID,
    clientSecret: process.env.DISCORD_CLIENT_SECRET,
    callbackURL: process.env.DISCORD_CALLBACK_URL,
    scope: ['identify']
  }, (accessToken, refreshToken, profile, done) => {
    db.get('SELECT * FROM users WHERE discord_id = ?', [profile.id], (err, row) => {
      if (err) return done(err);
      if (row) {
        return done(null, row);
      } else {
        // Create user as Member
        const id = 'u_' + uuidv4();
        db.run('INSERT INTO users(id, name, role, discord_id, created_at) VALUES(?,?,?,?,?)',
          [id, profile.username, 'Member', profile.id, Date.now()],
          function (err2) {
            if (err2) return done(err2);
            db.get('SELECT id, name, role, discord_id FROM users WHERE id = ?', [id], (e, r) => done(e, r));
          });
      }
    });
  }));
}

// Serve static frontend
app.use(express.static(path.join(__dirname, 'public')));

// --- DB init ---
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT,
      password_hash TEXT,
      role TEXT,
      discord_id TEXT,
      created_at INTEGER
    )
  `);
});

// --- Helpers ---
function requireAuth(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  if (req.session && req.session.userId) {
    db.get('SELECT id, name, role FROM users WHERE id = ?', [req.session.userId], (err, row) => {
      if (err || !row) return res.status(401).json({ error: 'Unauthorized' });
      req.user = row; return next();
    });
  } else {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

function requireAdmin(req, res, next) {
  const u = req.user;
  if (!u && req.session && req.session.userId) {
    db.get('SELECT id, name, role FROM users WHERE id = ?', [req.session.userId], (err, row) => {
      if (err || !row) return res.status(403).send('Forbidden');
      if (row.role === 'admin') { req.user = row; return next(); }
      return res.status(403).send('Forbidden');
    });
    return;
  }
  if (u && u.role === 'admin') return next();
  return res.status(403).send('Forbidden');
}

// --- Auth routes ---
// Local register (optional; not exposed in UI by default)
app.post('/auth/register', authLimiter, async (req, res) => {
  const { name, password } = req.body;
  if (!name || !password) return res.status(400).json({ error: 'Missing' });
  const hash = await bcrypt.hash(password, 12);
  const id = 'u_' + uuidv4();
  db.run('INSERT INTO users(id,name,password_hash,role,created_at) VALUES(?,?,?,?,?)',
    [id, name, hash, 'Member', Date.now()],
    function (err) {
      if (err) return res.status(500).json({ error: 'DB error' });
      res.json({ ok: true });
    });
});

// Local login
app.post('/auth/login', authLimiter, (req, res) => {
  const { name, password } = req.body;
  if (!name || !password) return res.status(400).json({ error: 'Missing fields' });
  db.get('SELECT id, name, password_hash, role FROM users WHERE name = ?', [name], async (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!row || !row.password_hash) return res.status(400).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok) return res.status(400).json({ error: 'Invalid credentials' });
    req.session.userId = row.id;
    req.session.save(() => res.json({ success: true, role: row.role }));
  });
});

// Logout
app.post('/auth/logout', (req, res) => {
  req.logout?.();
  req.session.destroy(() => {
    res.clearCookie('connect.sid', { path: '/' });
    res.json({ ok: true });
  });
});

// Discord OAuth
app.get('/auth/discord', passport.authenticate('discord'));
app.get('/auth/discord/callback',
  passport.authenticate('discord', { failureRedirect: '/login.html' }),
  (req, res) => {
    // On success: if admin -> admin page else home
    if (req.user && req.user.role === 'admin') return res.redirect('/admin.html');
    return res.redirect('/');
  });

// Protected admin-only API
app.get('/admin-data', requireAuth, requireAdmin, (req, res) => {
  // Sample secret data
  db.all('SELECT id, name, role, discord_id, created_at FROM users ORDER BY created_at DESC LIMIT 200', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json({ secret: 'Only for admin', users: rows, timestamp: Date.now() });
  });
});

// Endpoint to check "me"
app.get('/me', (req, res) => {
  if (req.isAuthenticated && req.isAuthenticated()) return res.json(req.user);
  if (req.session && req.session.userId) {
    db.get('SELECT id, name, role FROM users WHERE id = ?', [req.session.userId], (err, row) => {
      if (err || !row) return res.json(null);
      return res.json(row);
    });
  } else {
    return res.json(null);
  }
});

// Start server
app.listen(PORT, () => console.log(`Server listening on ${PORT} (BASE_URL=${BASE_URL}, FRONTEND_URL=${FRONTEND_URL})`));
