# KaranZeroDay — Full GitHub project (Frontend + Secure Backend)

This repo contains a modern animated dashboard (frontend) and a secure Node.js backend with:
- Local username/password login (bcrypt)
- Discord OAuth login
- Admin-only protected endpoints (role === 'admin')
- SQLite persistence
- Session-based auth (express-session + connect-sqlite3)
- Export/Import + demo features in frontend

## Files
- `public/index.html` — Modern dashboard (A)
- `public/admin.html` — Admin-only page (B)
- `public/login.html` — Login page (password & Discord)
- `server.js` — Backend server (API, auth, OAuth)
- `createAdmin.js` — CLI to create initial admin user
- `package.json`, `.gitignore`

## Quick Local Setup
1. Clone repo and `cd kz-dashboard-auth`.
2. `npm install`
3. Create `.env` file with:
