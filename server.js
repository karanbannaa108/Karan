// server.js
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
app.set('trust proxy', 1); // important behind proxies (Railway)
const PORT = process.env.PORT || 3000;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';
const SESSION_SECRET = process.env.SESSION_SECRET || 'change_this';
const DATABASE_URL = process.env.DATABASE_URL;
const NODE_ENV = process.env.NODE_ENV || 'development';

if (!DATABASE_URL) console.warn('WARNING: DATABASE_URL is not set');

const pool = new Pool({ connectionString: DATABASE_URL });

// in-memory map of running processes and logs (simple)
const runningBots = {}; // botId -> { proc, logLines: [], restarting }

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
      repo_url TEXT,
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
initDb().catch(err => console.error('DB init error', err));

// MIDDLEWARE
app.use(helmet());
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
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
    secure: NODE_ENV === 'production',
    httpOnly: true,
    sameSite: NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge: 1000 * 60 * 60 * 24
  }
}));

// Rate limiters
const apiLimiter = rateLimit({ windowMs: 60*1000, max: 60 });

// Helpers
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });
  next();
}
async function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });
  const { rows } = await pool.query('SELECT role FROM karanzero_users WHERE id=$1', [req.session.userId]);
  if (!rows[0] || rows[0].role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  next();
}
async function requireOwnerOrAdmin(req, res, next) {
  const botId = req.params.id;
  const { rows } = await pool.query('SELECT owner_id FROM karanzero_bots WHERE id=$1', [botId]);
  if (!rows[0]) return res.status(404).json({ error: 'Bot not found' });
  if (rows[0].owner_id === req.session.userId) return next();
  const u = await pool.query('SELECT role FROM karanzero_users WHERE id=$1', [req.session.userId]);
  if (u.rows[0] && u.rows[0].role === 'admin') return next();
  return res.status(403).json({ error: 'Forbidden' });
}

// STATIC
app.use(express.static(path.join(__dirname, 'public')));

// AUTH ROUTES (simple username/password + Discord OAuth)
app.post('/auth/register', apiLimiter, async (req,res)=>{
  const { name, password } = req.body;
  if (!name || !password) return res.status(400).json({ error:'Missing' });
  const id = 'kz_' + uuidv4();
  const hash = await bcrypt.hash(password, 12);
  try {
    await pool.query('INSERT INTO karanzero_users(id,name,password_hash,role,created_at) VALUES($1,$2,$3,$4,$5)', [id,name,hash,'Member',Date.now()]);
    res.json({ ok:true });
  } catch(err){
    if (err.code==='23505') return res.status(400).json({ error:'User exists' });
    console.error(err); res.status(500).json({ error:'DB error' });
  }
});

app.post('/auth/login', apiLimiter, async (req,res)=>{
  const { name, password } = req.body;
  if (!name || !password) return res.status(400).json({ error:'Missing' });
  try {
    const { rows } = await pool.query('SELECT id,password_hash,role FROM karanzero_users WHERE name=$1',[name]);
    const user = rows[0];
    if (!user) return res.status(400).json({ error:'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(400).json({ error:'Invalid credentials' });
    req.session.userId = user.id;
    res.json({ success:true, role:user.role });
  } catch(e){ console.error(e); res.status(500).json({ error:'Server' }); }
});

app.post('/auth/logout', (req,res)=>{
  req.session.destroy(()=> {
    res.clearCookie('connect.sid', { path: '/' });
    res.json({ ok:true });
  });
});

// /me
app.get('/me', async (req,res)=>{
  if (!req.session.userId) return res.json(null);
  const { rows } = await pool.query('SELECT id,name,role,discord_id FROM karanzero_users WHERE id=$1',[req.session.userId]);
  return res.json(rows[0] || null);
});

/* ---------------------
   FILE UPLOAD SETUP
   --------------------- */
const upload = multer({
  dest: path.join(os.tmpdir(), 'kz-bots'),
  limits: { fileSize: 50 * 1024 * 1024 } // 50MB limit
});

/* Upload endpoints
   Accepts: single .py file OR .zip archive of bot repo
*/
app.post('/upload-bot', requireAuth, upload.single('botfile'), apiLimiter, async (req,res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    // Validate extension
    const original = req.file.originalname || '';
    const ext = path.extname(original).toLowerCase();
    const botId = 'bot_' + uuidv4();
    const extractDir = path.join(os.tmpdir(), 'kz-bots', botId);
    fs.mkdirSync(extractDir, { recursive: true });

    let entryPoint = null;
    if (ext === '.zip') {
      // unzip
      const zip = new AdmZip(req.file.path);
      zip.extractAllTo(extractDir, true);
      // try to find a main .py (index.py, bot.py) or else take first .py
      const walk = (dir) => {
        const files = fs.readdirSync(dir);
        for (const f of files) {
          const fp = path.join(dir, f);
          const st = fs.statSync(fp);
          if (st.isDirectory()) {
            const found = walk(fp);
            if (found) return found;
          } else {
            if (f.toLowerCase() === 'bot.py' || f.toLowerCase() === 'main.py' || f.toLowerCase() === 'index.py') return fp;
          }
        }
        return null;
      };
      entryPoint = walk(extractDir);
      if (!entryPoint) {
        // find any .py
        const recFind = (d) => {
          const items = fs.readdirSync(d);
          for (const it of items) {
            const p = path.join(d,it);
            if (fs.statSync(p).isDirectory()) {
              const r = recFind(p); if (r) return r;
            } else if (p.endsWith('.py')) return p;
          }
          return null;
        };
        entryPoint = recFind(extractDir);
      }
      if (!entryPoint) return res.status(400).json({ error:'No .py file found in zip' });
    } else if (ext === '.py') {
      // single python file: move into folder
      const dest = path.join(extractDir, req.file.originalname);
      fs.renameSync(req.file.path, dest);
      entryPoint = dest;
    } else {
      // unsupported file
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error:'Unsupported file type. Upload .py or .zip' });
    }

    // optional: if requirements.txt present, install dependencies (non-blocking: spawn pip)
    const reqFile = path.join(path.dirname(entryPoint), 'requirements.txt');
    if (fs.existsSync(reqFile)) {
      // run pip install -r in that folder
      const pip = spawn('python3', ['-m', 'pip', 'install', '-r', reqFile, '--upgrade', '--no-warn-script-location'], { cwd: path.dirname(entryPoint) });
      pip.stdout.on('data', d => console.log('[pip]', d.toString()));
      pip.stderr.on('data', d => console.error('[pip err]', d.toString()));
      pip.on('close', code => console.log('pip exited', code));
    }

    // store metadata in DB
    await pool.query(
      'INSERT INTO karanzero_bots(id,name,owner_id,entry_point,runtime,file_path,status,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',
      [botId, req.file.originalname, req.session.userId, entryPoint, 'python', extractDir, 'uploaded', Date.now()]
    );

    res.json({ ok:true, botId });
  } catch (e) {
    console.error(e); res.status(500).json({ error:'Upload failed' });
  }
});

/* START / STOP bot processes and logs */

// helper to push logs into DB and memory
async function pushLog(botId, msg) {
  try {
    await pool.query('INSERT INTO karanzero_bot_logs(id,bot_id,msg,created_at) VALUES($1,$2,$3,$4)', [uuidv4(), botId, String(msg).slice(0,1000), Date.now()]);
  } catch(e){ console.error('pushLog err', e); }
  runningBots[botId] = runningBots[botId] || { proc: null, logLines: [] };
  runningBots[botId].logLines = (runningBots[botId].logLines || []).slice(-1000);
  runningBots[botId].logLines.push({ at: Date.now(), msg: String(msg) });
}

app.post('/bots/:id/start', requireAuth, requireOwnerOrAdmin, apiLimiter, async (req,res) => {
  const botId = req.params.id;
  try {
    const { rows } = await pool.query('SELECT * FROM karanzero_bots WHERE id=$1', [botId]);
    if (!rows[0]) return res.status(404).json({ error:'Bot not found' });
    const bot = rows[0];
    if (!bot.entry_point || !fs.existsSync(bot.entry_point)) return res.status(400).json({ error:'Entry point missing' });

    if (runningBots[botId] && runningBots[botId].proc) return res.json({ ok:true, status:'already running' });

    // spawn python process
    const env = Object.assign({}, process.env, (bot.env || {}));
    const proc = spawn('python3', [bot.entry_point], { cwd: path.dirname(bot.entry_point), env });

    runningBots[botId] = { proc, logLines: [] };

    proc.stdout.on('data', async (d) => {
      const s = d.toString();
      console.log(`[bot ${botId}]`, s);
      await pushLog(botId, s);
    });
    proc.stderr.on('data', async (d) => {
      const s = d.toString();
      console.error(`[bot ${botId} ERR]`, s);
      await pushLog(botId, '[ERR] ' + s);
    });

    proc.on('close', async (code, sig) => {
      await pool.query('UPDATE karanzero_bots SET status=$1 WHERE id=$2', ['stopped', botId]);
      await pushLog(botId, `process exited code=${code} sig=${sig}`);
      runningBots[botId].proc = null;
    });

    await pool.query('UPDATE karanzero_bots SET status=$1 WHERE id=$2', ['running', botId]);
    await pushLog(botId, 'started');
    res.json({ ok:true, status:'running' });
  } catch(e){ console.error(e); res.status(500).json({ error:'Start failed' }); }
});

app.post('/bots/:id/stop', requireAuth, requireOwnerOrAdmin, apiLimiter, async (req,res) => {
  const botId = req.params.id;
  try {
    if (!runningBots[botId] || !runningBots[botId].proc) {
      await pool.query('UPDATE karanzero_bots SET status=$1 WHERE id=$2', ['stopped', botId]);
      return res.json({ ok:true, status:'stopped' });
    }
    const p = runningBots[botId].proc;
    p.kill();
    runningBots[botId].proc = null;
    await pool.query('UPDATE karanzero_bots SET status=$1 WHERE id=$2', ['stopped', botId]);
    await pushLog(botId, 'stopped by user');
    res.json({ ok:true, status:'stopped' });
  } catch(e){ console.error(e); res.status(500).json({ error:'Stop failed' }); }
});

app.get('/bots/:id/logs', requireAuth, requireOwnerOrAdmin, apiLimiter, async (req,res) => {
  const botId = req.params.id;
  try {
    // return last 200 log lines from memory + DB fallback
    const mem = runningBots[botId] && runningBots[botId].logLines ? runningBots[botId].logLines.slice(-200) : [];
    const { rows } = await pool.query('SELECT msg,created_at FROM karanzero_bot_logs WHERE bot_id=$1 ORDER BY created_at DESC LIMIT 500', [botId]);
    const dbLines = rows.map(r => ({ at: r.created_at, msg: r.msg })).slice(0,500);
    const merged = [...dbLines.reverse(), ...mem.map(x=>({ at:x.at, msg:x.msg }))].slice(-500);
    res.json(merged);
  } catch(e){ console.error(e); res.status(500).json({ error:'Logs failed' }); }
});

// CRUD bots: create/edit/delete/list
app.post('/bots', requireAuth, apiLimiter, async (req,res) => {
  const { name, repo_url, entry_point, envVars } = req.body;
  if (!name) return res.status(400).json({ error:'Missing name' });
  const id = 'bot_' + uuidv4();
  try {
    await pool.query('INSERT INTO karanzero_bots(id,name,owner_id,entry_point,repo_url,env,status,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',
      [id,name,req.session.userId,entry_point||null,repo_url||null,JSON.stringify(envVars||{}),'stopped',Date.now()]);
    res.json({ ok:true, id });
  } catch(e){ console.error(e); res.status(500).json({ error:'Create failed' }); }
});

app.get('/bots', requireAuth, apiLimiter, async (req,res) => {
  try {
    const u = await pool.query('SELECT role FROM karanzero_users WHERE id=$1', [req.session.userId]);
    const role = u.rows[0] ? u.rows[0].role : 'Member';
    let rows;
    if (role === 'admin') {
      ({ rows } = await pool.query('SELECT * FROM karanzero_bots ORDER BY created_at DESC'));
    } else {
      ({ rows } = await pool.query('SELECT * FROM karanzero_bots WHERE owner_id=$1 ORDER BY created_at DESC',[req.session.userId]));
    }
    res.json(rows);
  } catch(e){ console.error(e); res.status(500).json({ error:'List failed' }); }
});

app.get('/bots/:id', requireAuth, requireOwnerOrAdmin, apiLimiter, async (req,res) => {
  const { rows } = await pool.query('SELECT * FROM karanzero_bots WHERE id=$1',[req.params.id]);
  if (!rows[0]) return res.status(404).json({ error:'Not found' });
  res.json(rows[0]);
});

app.put('/bots/:id', requireAuth, requireOwnerOrAdmin, apiLimiter, async (req,res) => {
  const { name, repo_url, entry_point, envVars } = req.body;
  try {
    await pool.query('UPDATE karanzero_bots SET name=$1, repo_url=$2, entry_point=$3, env=$4 WHERE id=$5',
      [name, repo_url, entry_point, JSON.stringify(envVars||{}), req.params.id]);
    res.json({ ok:true });
  } catch(e){ console.error(e); res.status(500).json({ error:'Update failed' }); }
});

app.delete('/bots/:id', requireAuth, requireOwnerOrAdmin, apiLimiter, async (req,res) => {
  try {
    // stop if running
    if (runningBots[req.params.id] && runningBots[req.params.id].proc) {
      runningBots[req.params.id].proc.kill();
      runningBots[req.params.id].proc = null;
    }
    await pool.query('DELETE FROM karanzero_bots WHERE id=$1',[req.params.id]);
    res.json({ ok:true });
  } catch(e){ console.error(e); res.status(500).json({ error:'Delete failed' }); }
});

// error handler
app.use((err, req, res, next) => {
  console.error('ERR', err);
  res.status(500).json({ error:'Server error' });
});

app.listen(PORT, () => console.log(`KaranZeroDay backend listening on ${PORT}`));
