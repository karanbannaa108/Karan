# KaranZeroDay Backend

## Overview
Express backend + Postgres sessions + Discord OAuth + Username login.
Users saved in table `karanzero_users`. Sessions in `karanzero_sessions`.

## Local
1. copy .env.example -> .env and fill values
2. npm install
3. npm run create-admin   # create admin user
4. npm start
5. open http://localhost:3000/login.html

## Deploy (Railway)
1. Push repo to GitHub.
2. Create Railway project and connect repo (service name = Karan).
3. Add Postgres plugin (Railway) -> it provides `Postgres.DATABASE_URL`.
4. In backend service Variables add:
   - DATABASE_URL = ${{ Postgres.DATABASE_URL }}
   - SESSION_SECRET = <long secret>
   - FRONTEND_URL = https://karan-psi.vercel.app
   - DISCORD_CLIENT_ID
   - DISCORD_CLIENT_SECRET
   - DISCORD_REDIRECT = https://<your-railway-app>/auth/discord/callback
   - NODE_ENV = production
5. Generate domain for backend (Settings → Public Networking → Generate Domain).
6. Deploy and then run `npm run create-admin` in Railway Shell to create admin.

## Frontend (Vercel)
- Deploy `public/` (or set project root) to Vercel.
- Set `BASE_API` inside `public/*.html` or serve server-side variable mapping.
- Ensure `FRONTEND_URL` in Railway matches your Vercel domain.

## Notes
- Do NOT commit .env
- Use strong SESSION_SECRET
- If using SSL/hosted DB, you may need PG ssl config in server.js
