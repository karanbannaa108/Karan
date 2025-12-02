// ---------------------------------------------------------
// KaranZeroDay — FULL BOT HOSTING BACKEND
// Python .py / .zip upload, extract, install, run, stop,
// logs, auto-restart, env encryption, admin system
// ---------------------------------------------------------

require("dotenv").config();
const express = require("express");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const path = require("path");
const fs = require("fs");
const os = require("os");
const bcrypt = require("bcrypt");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");
const multer = require("multer");
const AdmZip = require("adm-zip");
const { spawn } = require("child_process");

const app = express();
app.set("trust proxy", 1);

const PORT = process.env.PORT || 3000;
const FRONTEND_URL = process.env.FRONTEND_URL;
const SESSION_SECRET = process.env.SESSION_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;
const ENC_KEY = process.env.DATA_ENCRYPT_KEY || null; // base64 32 bytes
const NODE_ENV = process.env.NODE_ENV || "development";

const pool = new Pool({ connectionString: DATABASE_URL });

// --------------------------------------
// INIT DATABASE
// --------------------------------------
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

// --------------------------------------
// ENCRYPTION HELPERS
// --------------------------------------
function isEncReady() {
  return ENC_KEY && ENC_KEY.length > 0;
}
function encryptText(plain) {
  if (!isEncReady()) return plain;

  const key = Buffer.from(ENC_KEY, "base64");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString("base64")}:${tag.toString("base64")}:${enc.toString(
    "base64"
  )}`;
}
function decryptText(payload) {
  if (!isEncReady()) return payload;

  const key = Buffer.from(ENC_KEY, "base64");
  const [iv64, tag64, data64] = payload.split(":");
  const iv = Buffer.from(iv64, "base64");
  const tag = Buffer.from(tag64, "base64");
  const data = Buffer.from(data64, "base64");

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(data), decipher.final()]);
  return dec.toString("utf8");
}
function maybeEncryptEnv(obj) {
  if (!obj || typeof obj !== "object") return {};

  const out = {};
  for (let k in obj) {
    const keyU = k.toUpperCase();
    const v = obj[k];

    if (
      isEncReady() &&
      (keyU.includes("TOKEN") ||
        keyU.includes("SECRET") ||
        keyU.includes("KEY") ||
        keyU.includes("PASSWORD"))
    ) {
      out[k] = "enc:" + encryptText(String(v));
    } else out[k] = v;
  }
  return out;
}

// --------------------------------------
// MIDDLEWARE
// --------------------------------------
app.use(helmet());
app.use(express.json({ limit: "4mb" }));
app.use(cookieParser());

app.use(
  cors({
    origin: FRONTEND_URL,
    credentials: true,
  })
);

app.use(
  session({
    store: new PgSession({ pool }),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: NODE_ENV === "production",
      httpOnly: true,
      sameSite: NODE_ENV === "production" ? "none" : "lax",
      maxAge: 24 * 60 * 60 * 1000,
    },
  })
);

app.use(express.static("public"));

const limiter = rateLimit({ windowMs: 60 * 1000, max: 100 });

// --------------------------------------
// AUTH HELPERS
// --------------------------------------
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "Not logged in" });
  next();
}

async function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "Not logged in" });

  const q = await pool.query("SELECT role FROM karanzero_users WHERE id=$1", [
    req.session.userId,
  ]);
  if (!q.rows[0] || q.rows[0].role !== "admin")
    return res.status(403).json({ error: "Admin only" });

  next();
}

async function requireOwnerOrAdmin(req, res, next) {
  const botId = req.params.id;
  const r = await pool.query(
    "SELECT owner_id FROM karanzero_bots WHERE id=$1",
    [botId]
  );

  if (!r.rows.length) return res.status(404).json({ error: "Bot not found" });

  if (r.rows[0].owner_id === req.session.userId) return next();

  const u = await pool.query("SELECT role FROM karanzero_users WHERE id=$1", [
    req.session.userId,
  ]);
  if (u.rows[0] && u.rows[0].role === "admin") return next();

  return res.status(403).json({ error: "Forbidden" });
}

// --------------------------------------
// AUTH ROUTES
// --------------------------------------
app.post("/auth/register", limiter, async (req, res) => {
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

app.post("/auth/login", limiter, async (req, res) => {
  const { name, password } = req.body;

  const q = await pool.query("SELECT * FROM karanzero_users WHERE name=$1", [
    name,
  ]);
  if (!q.rows.length) return res.json({ error: "Invalid" });

  const user = q.rows[0];
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.json({ error: "Invalid" });

  req.session.userId = user.id;

  res.json({ ok: true, role: user.role });
});

app.get("/me", async (req, res) => {
  if (!req.session.userId) return res.json(null);

  const q = await pool.query(
    "SELECT id,name,role FROM karanzero_users WHERE id=$1",
    [req.session.userId]
  );
  res.json(q.rows[0]);
});

// --------------------------------------
// ADMIN ROUTES
// --------------------------------------
app.get("/admin/users", requireAdmin, async (req, res) => {
  const q = await pool.query(
    "SELECT id,name,role FROM karanzero_users ORDER BY created_at DESC"
  );
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
  await pool.query("DELETE FROM karanzero_users WHERE id=$1", [req.body.id]);
  res.json({ ok: true });
});

// --------------------------------------
// UPLOAD (.py / .zip)
// --------------------------------------
const upload = multer({
  dest: path.join(os.tmpdir(), "kz-bots"),
  limits: { fileSize: 50 * 1024 * 1024 },
});

async function pushLog(botId, msg) {
  await pool.query(
    "INSERT INTO karanzero_bot_logs(id,bot_id,msg,created_at) VALUES($1,$2,$3,$4)",
    [uuidv4(), botId, msg.slice(0, 1000), Date.now()]
  );
}

const runningBots = {}; // botId → {proc, logs[], restarts, sseClients:Set() }

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
  } else if (ext === ".zip") {
    const zip = new AdmZip(req.file.path);
    zip.extractAllTo(baseDir, true);

    function findPy(dir) {
      const items = fs.readdirSync(dir);
      for (const i of items) {
        const full = path.join(dir, i);
        if (fs.statSync(full).isDirectory()) {
          const deep = findPy(full);
          if (deep) return deep;
        }
        if (full.endsWith(".py")) return full;
      }
      return null;
    }

    entryPoint = findPy(baseDir);
    if (!entryPoint) return res.json({ error: "No .py found" });
  } else return res.json({ error: "Invalid file type" });

  await pool.query(
    "INSERT INTO karanzero_bots(id,name,owner_id,entry_point,runtime,file_path,env,status,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    [
      botId,
      req.file.originalname,
      req.session.userId,
      entryPoint,
      "python",
      baseDir,
      JSON.stringify({}),
      "uploaded",
      Date.now(),
    ]
  );

  res.json({ ok: true, botId });
});

// --------------------------------------
// AUTO-RESTART SPAWN LOGIC
// --------------------------------------
async function startBotProcess(bot) {
  const botId = bot.id;

  runningBots[botId] = runningBots[botId] || {
    proc: null,
    logs: [],
    restarts: 0,
    sseClients: new Set(),
  };

  if (runningBots[botId].proc)
    return { ok: true, status: "already running" };

  // Prepare ENV
  let envObj = {};
  try {
    envObj =
      typeof bot.env === "object"
        ? bot.env
        : bot.env
        ? JSON.parse(bot.env)
        : {};
  } catch {
    envObj = {};
  }

  for (let k in envObj) {
    if (typeof envObj[k] === "string" && envObj[k].startsWith("enc:")) {
      envObj[k] = decryptText(envObj[k].slice(4));
    }
  }

  const spawnEnv = { ...process.env, ...envObj };

  function spawnNow() {
    const proc = spawn("python3", [bot.entry_point], {
      cwd: path.dirname(bot.entry_point),
      env: spawnEnv,
    });

    runningBots[botId].proc = proc;

    proc.stdout.on("data", async (d) => {
      const s = d.toString();
      runningBots[botId].logs.push(s);
      if (runningBots[botId].logs.length > 5000)
        runningBots[botId].logs.shift();

      await pushLog(botId, s);
      runningBots[botId].sseClients.forEach((c) =>
        c.write(`data: ${JSON.stringify({ type: "stdout", msg: s })}\n\n`)
      );
    });

    proc.stderr.on("data", async (d) => {
      const s = "[ERR] " + d.toString();
      runningBots[botId].logs.push(s);
      await pushLog(botId, s);
      runningBots[botId].sseClients.forEach((c) =>
        c.write(`data: ${JSON.stringify({ type: "stderr", msg: s })}\n\n`)
      );
    });

    proc.on("close", async () => {
      await pool.query("UPDATE karanzero_bots SET status=$1 WHERE id=$2", [
        "stopped",
        botId,
      ]);
      await pushLog(botId, "process exited");

      const max = 3;
      if (runningBots[botId].restarts < max) {
        runningBots[botId].restarts++;
        const wait = 1000 * Math.pow(2, runningBots[botId].restarts);
        await pushLog(botId, `auto-restart in ${wait}ms`);

        setTimeout(async () => {
          const again = await pool.query(
            "SELECT * FROM karanzero_bots WHERE id=$1",
            [botId]
          );
          if (again.rows[0]) {
            spawnNow();
            await pool.query(
              "UPDATE karanzero_bots SET status=$1 WHERE id=$2",
              ["restarting", botId]
            );
          }
        }, wait);
      } else {
        await pushLog(botId, "auto-restart failed, marking error");
        await pool.query(
          "UPDATE karanzero_bots SET status=$1 WHERE id=$2",
          ["error", botId]
        );
      }
    });
  }

  spawnNow();

  await pool.query("UPDATE karanzero_bots SET status='running' WHERE id=$1", [
    botId,
  ]);

  return { ok: true, status: "running" };
}

// --------------------------------------
// BOT START
// --------------------------------------
app.post("/bots/:id/start", requireOwnerOrAdmin, async (req, res) => {
  const botId = req.params.id;

  const q = await pool.query("SELECT * FROM karanzero_bots WHERE id=$1", [
    botId,
  ]);
  if (!q.rows.length) return res.json({ error: "Not found" });

  const bot = q.rows[0];
  const r = await startBotProcess(bot);
  res.json(r);
});

// --------------------------------------
// BOT STOP
// --------------------------------------
app.post("/bots/:id/stop", requireOwnerOrAdmin, async (req, res) => {
  const botId = req.params.id;

  if (runningBots[botId]?.proc) runningBots[botId].proc.kill();

  runningBots[botId].proc = null;

  await pool.query("UPDATE karanzero_bots SET status='stopped' WHERE id=$1", [
    botId,
  ]);
  await pushLog(botId, "Bot stopped");

  res.json({ ok: true });
});

// --------------------------------------
// LOG STREAM (SSE)
// --------------------------------------
app.get("/bots/:id/stream", requireOwnerOrAdmin, (req, res) => {
  const botId = req.params.id;

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();

  if (!runningBots[botId])
    runningBots[botId] = { proc: null, logs: [], restarts: 0, sseClients: new Set() };

  runningBots[botId].sseClients.add(res);

  // send latest logs
  for (const line of runningBots[botId].logs.slice(-200)) {
    res.write(`data: ${JSON.stringify({ type: "init", msg: line })}\n\n`);
  }

  const ping = setInterval(() => res.write(":\n\n"), 20000);

  req.on("close", () => {
    clearInterval(ping);
    runningBots[botId].sseClients.delete(res);
  });
});

// --------------------------------------
// BOT LOGS (NORMAL POLL)
// --------------------------------------
app.get("/bots/:id/logs", requireOwnerOrAdmin, async (req, res) => {
  const botId = req.params.id;

  const q = await pool.query(
    "SELECT msg,created_at FROM karanzero_bot_logs WHERE bot_id=$1 ORDER BY created_at DESC LIMIT 200",
    [botId]
  );

  res.json(q.rows.reverse());
});

// --------------------------------------
// BOT LIST & DELETE
// --------------------------------------
app.get("/bots", requireAuth, async (req, res) => {
  const u = await pool.query("SELECT role FROM karanzero_users WHERE id=$1", [
    req.session.userId,
  ]);
  const admin = u.rows[0]?.role === "admin";

  const q = admin
    ? await pool.query("SELECT * FROM karanzero_bots ORDER BY created_at DESC")
    : await pool.query(
        "SELECT * FROM karanzero_bots WHERE owner_id=$1 ORDER BY created_at DESC",
        [req.session.userId]
      );

  res.json(q.rows);
});

app.delete("/bots/:id", requireOwnerOrAdmin, async (req, res) => {
  const botId = req.params.id;

  if (runningBots[botId]?.proc) runningBots[botId].proc.kill();

  await pool.query("DELETE FROM karanzero_bots WHERE id=$1", [botId]);

  res.json({ ok: true });
});

// --------------------------------------
// START SERVER
// --------------------------------------
app.listen(PORT, () =>
  console.log("🔥 KaranZeroDay Backend running on port", PORT)
);
