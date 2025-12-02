// server.js — FINAL COMPLETE VERSION
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const path = require('path');
const fs = require('fs');
const os = require('os');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const AdmZip = require('adm-zip');
const { spawn } = require('child_process');

const app = express();
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;
const FRONTEND_URL = process.env.FRONTEND_URL;
const SESSION_SECRET = process.env.SESSION_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;
const NODE_ENV = process.env.NODE_ENV || "development";

const pool = new Pool({ connectionString: DATABASE_URL });

/* ---------------------------
   DATABASE SETUP
---------------------------- */
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

  await pool.query(`
    CREATE TABLE IF NOT EXISTS karanzero_bots (
      id TEXT PRIMARY KEY,
      name TEXT,
      owner_id TEXT,
      entry_point TEXT,
      runtime TEXT,
      file_path TEXT,
      env JSONB,
      status TEXT,
      created_at BIGINT
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS karanzero_bot_logs (
      id TEXT PRIMARY KEY,
      bot_id TEXT,
      msg TEXT,
      created_at BIGINT
    );
  `);
}
initDb();

/* ---------------------------
   MIDDLEWARE
---------------------------- */
app.use(helmet());
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());

app.use(cors({
  origin: FRONTEND_URL,
  credentials: true
}));

app.use(session({
  store: new PgSession({ pool }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: NODE_ENV === "production",
    httpOnly: true,
    sameSite: NODE_ENV === "production" ? "none" : "lax",
    maxAge: 1000 * 60 * 60 * 24
  }
}));

app.use(express.static("public"));

const limiter = rateLimit({ windowMs: 60000, max: 100 });
app.use("/auth", limiter);

/* ---------------------------
   AUTH HELPERS
---------------------------- */
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "Not logged in" });
  next();
}

async function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "Not logged in" });
  const q = await pool.query("SELECT role FROM karanzero_users WHERE id=$1", [req.session.userId]);
  if (!q.rows[0] || q.rows[0].role !== "admin") return res.status(403).json({ error: "Admin only" });
  next();
}

async function requireOwnerOrAdmin(req, res, next) {
  const botId = req.params.id;
  const r = await pool.query("SELECT owner_id FROM karanzero_bots WHERE id=$1", [botId]);
  if (!r.rows.length) return res.status(404).json({ error: "Bot not found" });

  if (r.rows[0].owner_id === req.session.userId) return next();

  const u = await pool.query("SELECT role FROM karanzero_users WHERE id=$1", [req.session.userId]);
  if (u.rows[0] && u.rows[0].role === "admin") return next();

  return res.status(403).json({ error: "Forbidden" });
}

/* ---------------------------
   LOGIN / REGISTER / /ME
---------------------------- */
app.post("/auth/register", async (req, res) => {
  const { name, password } = req.body;
  if (!name || !password) return res.json({ error: "Missing" });

  const id = "kz_" + uuidv4();
  const hash = await bcrypt.hash(password, 12);

  try {
    await pool.query(
      "INSERT INTO karanzero_users(id,name,password_hash,role,created_at) VALUES($1,$2,$3,$4,$5)",
      [id, name, hash, "Member", Date.now()]
    );
    res.json({ ok: true });
  } catch {
    res.json({ error: "User exists" });
  }
});

app.post("/auth/login", async (req, res) => {
  const { name, password } = req.body;

  const u = await pool.query("SELECT * FROM karanzero_users WHERE name=$1", [name]);
  if (!u.rows.length) return res.json({ error: "Invalid" });

  const user = u.rows[0];
  const match = await bcrypt.compare(password, user.password_hash);

  if (!match) return res.json({ error: "Invalid" });

  req.session.userId = user.id;

  res.json({ ok: true, role: user.role });
});

app.get("/me", async (req, res) => {
  if (!req.session.userId) return res.json(null);
  const u = await pool.query("SELECT id,name,role FROM karanzero_users WHERE id=$1", [req.session.userId]);
  res.json(u.rows[0]);
});

/* ---------------------------
   ADMIN ROUTES
---------------------------- */
app.get("/admin/users", requireAdmin, async (req, res) => {
  const q = await pool.query("SELECT id,name,role FROM karanzero_users ORDER BY created_at DESC");
  res.json(q.rows);
});

app.post("/admin/create-user", requireAdmin, async (req, res) => {
  const { name, password, role } = req.body;
  const id = "kz_" + uuidv4();
  const hash = await bcrypt.hash(password, 12);

  await pool.query(
    "INSERT INTO karanzero_users(id,name,password_hash,role,created_at) VALUES($1,$2,$3,$4,$5)",
    [id, name, hash, role, Date.now()]
  );

  res.json({ ok: true });
});

app.post("/admin/delete-user", requireAdmin, async (req, res) => {
  const { id } = req.body;
  await pool.query("DELETE FROM karanzero_users WHERE id=$1", [id]);
  res.json({ ok: true });
});

/* ---------------------------
  BOT UPLOAD (.py / .zip)
---------------------------- */
const upload = multer({
  dest: path.join(os.tmpdir(), "kz-bots"),
  limits: { fileSize: 50 * 1024 * 1024 }
});

const runningBots = {}; // { botId: { proc, logs[] } }

async function pushLog(botId, msg) {
  await pool.query(
    "INSERT INTO karanzero_bot_logs(id,bot_id,msg,created_at) VALUES($1,$2,$3,$4)",
    [uuidv4(), botId, msg.slice(0, 1000), Date.now()]
  );
}

app.post("/upload-bot", requireAuth, upload.single("botfile"), async (req, res) => {
  if (!req.file) return res.json({ error: "No file" });

  const botId = "bot_" + uuidv4();
  const ext = path.extname(req.file.originalname).toLowerCase();
  const baseDir = path.join(os.tmpdir(), "kz-bots", botId);

  fs.mkdirSync(baseDir, { recursive: true });

  let entryPoint = "";

  if (ext === ".py") {
    const dest = path.join(baseDir, req.file.originalname);
    fs.renameSync(req.file.path, dest);
    entryPoint = dest;
  }

  else if (ext === ".zip") {
    const zip = new AdmZip(req.file.path);
    zip.extractAllTo(baseDir, true);

    const findPy = (dir) => {
      const items = fs.readdirSync(dir);
      for (const i of items) {
        const full = path.join(dir, i);
        if (fs.statSync(full).isDirectory()) {
          const r = findPy(full);
          if (r) return r;
        }
        if (i.endsWith(".py")) return full;
      }
      return null;
    };

    entryPoint = findPy(baseDir);
    if (!entryPoint) return res.json({ error: "No .py file found in zip" });
  }

  else return res.json({ error: "Invalid file type" });

  await pool.query(
    "INSERT INTO karanzero_bots(id,name,owner_id,entry_point,runtime,file_path,status,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
    [botId, req.file.originalname, req.session.userId, entryPoint, "python", baseDir, "uploaded", Date.now()]
  );

  res.json({ ok: true, botId });
});

/* ---------------------------
   BOT START
---------------------------- */
app.post("/bots/:id/start", requireOwnerOrAdmin, async (req, res) => {
  const botId = req.params.id;
  const q = await pool.query("SELECT * FROM karanzero_bots WHERE id=$1", [botId]);
  if (!q.rows.length) return res.json({ error: "Not found" });

  const bot = q.rows[0];

  if (runningBots[botId]?.proc) return res.json({ ok: true, status: "already running" });

  const proc = spawn("python3", [bot.entry_point], {
    cwd: path.dirname(bot.entry_point),
    env: { ...process.env }
  });

  runningBots[botId] = { proc, logs: [] };

  proc.stdout.on("data", async (d) => {
    const msg = d.toString();
    runningBots[botId].logs.push(msg);
    await pushLog(botId, msg);
  });

  proc.stderr.on("data", async (d) => {
    const msg = "[ERR] " + d.toString();
    runningBots[botId].logs.push(msg);
    await pushLog(botId, msg);
  });

  proc.on("close", async () => {
    await pool.query("UPDATE karanzero_bots SET status='stopped' WHERE id=$1", [botId]);
  });

  await pool.query("UPDATE karanzero_bots SET status='running' WHERE id=$1", [botId]);

  res.json({ ok: true, status: "running" });
});

/* ---------------------------
   BOT STOP
---------------------------- */
app.post("/bots/:id/stop", requireOwnerOrAdmin, async (req, res) => {
  const botId = req.params.id;

  const bot = runningBots[botId];
  if (!bot || !bot.proc) {
    await pool.query("UPDATE karanzero_bots SET status='stopped' WHERE id=$1", [botId]);
    return res.json({ ok: true, status: "stopped" });
  }

  bot.proc.kill();
  runningBots[botId].proc = null;

  await pool.query("UPDATE karanzero_bots SET status='stopped' WHERE id=$1", [botId]);
  await pushLog(botId, "Bot stopped");

  res.json({ ok: true });
});

/* ---------------------------
   BOT LOGS
---------------------------- */
app.get("/bots/:id/logs", requireOwnerOrAdmin, async (req, res) => {
  const botId = req.params.id;

  const q = await pool.query(
    "SELECT msg,created_at FROM karanzero_bot_logs WHERE bot_id=$1 ORDER BY created_at DESC LIMIT 100",
    [botId]
  );

  res.json(q.rows.reverse());
});

/* ---------------------------
   BOT LIST / VIEW / DELETE
---------------------------- */
app.get("/bots", requireAuth, async (req, res) => {
  const me = await pool.query("SELECT role FROM karanzero_users WHERE id=$1", [req.session.userId]);
  const admin = me.rows[0]?.role === "admin";

  const q = admin
    ? await pool.query("SELECT * FROM karanzero_bots ORDER BY created_at DESC")
    : await pool.query("SELECT * FROM karanzero_bots WHERE owner_id=$1 ORDER BY created_at DESC", [req.session.userId]);

  res.json(q.rows);
});

app.delete("/bots/:id", requireOwnerOrAdmin, async (req, res) => {
  const botId = req.params.id;

  if (runningBots[botId]?.proc) runningBots[botId].proc.kill();

  await pool.query("DELETE FROM karanzero_bots WHERE id=$1", [botId]);

  res.json({ ok: true });
});

/* ---------------------------
   START SERVER
---------------------------- */
app.listen(PORT, () => console.log("Server running on", PORT));
