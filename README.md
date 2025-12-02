# KaranZeroDay Backend (Postgres, Discord OAuth, Sessions)

## Setup (local)
1. git clone ...
2. npm install
3. create .env with DATABASE_URL, SESSION_SECRET, FRONTEND_URL, DISCORD_*
4. npm run create-admin
5. npm start
6. Open http://localhost:3000/

## Deploy (Railway)
1. Push repo to GitHub.
2. On Railway create new project → Deploy from GitHub.
3. In Railway, set environment variables:
   - DATABASE_URL (Railway Postgres connection string)
   - SESSION_SECRET (strong random)
   - FRONTEND_URL = https://your-vercel-app.vercel.app
   - DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET
   - DISCORD_REDIRECT = https://your-railway-url.up.railway.app/auth/discord/callback
   - NODE_ENV = production
4. Deploy. Railway will provision Postgres and run `npm install` then start.
5. In Railway "Schedule" or "Shell" run `npm run create-admin` to create your admin.

## Deploy frontend (Vercel)
- Point Vercel to repo and set Output Directory: `public`.
- If frontend needs to call backend cross-domain, edit `public/login.html` & `public/admin.html` to set `const BASE_API = 'https://your-railway-url.up.railway.app'` or configure environment.
- Use `credentials: 'include'` in fetch (already in templates).
