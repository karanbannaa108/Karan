require("dotenv").config();
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
const { v4: uuid } = require("uuid");

const app = express();
const PORT = process.env.PORT || 3000;

const FRONTEND_URL = process.env.FRONTEND_URL || "*";
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_REDIRECT = process.env.DISCORD_REDIRECT;

// database
const db = new sqlite3.Database("database.sqlite");
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT,
      password_hash TEXT,
      role TEXT,
      discord_id TEXT,
      created_at INT
    )
  `);
});

// security
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(cors({
  origin: FRONTEND_URL,
  credentials: true
}));

// session
app.use(session({
  genid: () => uuid(),
  store: new SQLiteStore({ db: "sessions.sqlite", dir: "./" }),
  secret: process.env.SESSION_SECRET || "SECRET",
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,
    httpOnly: true,
    sameSite: "lax"
  }
}));

// middleware
const requireAuth = (req, res, next) => {
  if (!req.session.userId) return res.status(401).json({ error: "Unauthorized" });
  next();
};

const requireAdmin = (req, res, next) => {
  db.get("SELECT role FROM users WHERE id = ?", [req.session.userId], (err, row) => {
    if (!row || row.role !== "admin") return res.status(403).json({ error: "Forbidden" });
    next();
  });
};

// LOGIN (username + password)
app.post("/auth/login", (req, res) => {
  const { name, password } = req.body;

  db.get("SELECT * FROM users WHERE name = ?", [name], async (err, row) => {
    if (!row) return res.json({ error: "Invalid credentials" });

    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok) return res.json({ error: "Invalid credentials" });

    req.session.userId = row.id;
    res.json({ success: true, role: row.role });
  });
});

// LOGOUT
app.post("/auth/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ success: true });
  });
});

// DISCORD LOGIN — Step 1 (redirect)
app.get("/auth/discord", (req, res) => {
  const url =
    `https://discord.com/api/oauth2/authorize?client_id=${DISCORD_CLIENT_ID}` +
    `&redirect_uri=${encodeURIComponent(DISCORD_REDIRECT)}` +
    `&response_type=code&scope=identify`;

  res.redirect(url);
});

// DISCORD CALLBACK — Step 2
app.get("/auth/discord/callback", async (req, res) => {
  const code = req.query.code;
  if (!code) return res.redirect("/login.html");

  // exchange code for token
  const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body:
      `client_id=${DISCORD_CLIENT_ID}` +
      `&client_secret=${DISCORD_CLIENT_SECRET}` +
      `&grant_type=authorization_code` +
      `&code=${code}` +
      `&redirect_uri=${encodeURIComponent(DISCORD_REDIRECT)}`
  });

  const token = await tokenRes.json();
  if (!token.access_token) return res.redirect("/login.html");

  // get user info
  const userRes = await fetch("https://discord.com/api/users/@me", {
    headers: { Authorization: `Bearer ${token.access_token}` }
  });

  const discordUser = await userRes.json();

  // save or create user
  db.get("SELECT * FROM users WHERE discord_id = ?", [discordUser.id], (err, row) => {
    if (row) {
      req.session.userId = row.id;
      return res.redirect("/admin.html");
    }

    // create new user
    const id = uuid();
    db.run(
      "INSERT INTO users(id, name, role, discord_id, created_at) VALUES (?,?,?,?,?)",
      [id, discordUser.username, "Member", discordUser.id, Date.now()],
      () => {
        req.session.userId = id;
        res.redirect("/");
      }
    );
  });
});

// ADMIN PANEL DATA
app.get("/admin-data", requireAuth, requireAdmin, (req, res) => {
  db.all("SELECT id, name, role, discord_id FROM users", [], (err, rows) => {
    res.json({
      message: "Admin Access Granted",
      users: rows
    });
  });
});

// GET CURRENT USER
app.get("/me", (req, res) => {
  if (!req.session.userId) return res.json(null);

  db.get(
    "SELECT id, name, role, discord_id FROM users WHERE id = ?",
    [req.session.userId],
    (err, row) => res.json(row || null)
  );
});

// static
app.use(express.static("public"));

app.listen(PORT, () => console.log("Backend running on", PORT));
