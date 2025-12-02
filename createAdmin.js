// createAdmin.js
require('dotenv').config();
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const readline = require('readline');
const { v4: uuidv4 } = require('uuid');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

rl.question('Admin username: ', (name) => {
  rl.question('Admin password: ', async (pwd) => {
    const hash = await bcrypt.hash(pwd, 12);
    const id = 'kz_' + uuidv4();
    try {
      await pool.query('INSERT INTO karanzero_users(id,name,password_hash,role,created_at) VALUES($1,$2,$3,$4,$5)', [id, name, hash, 'admin', Date.now()]);
      console.log('Admin created:', name);
    } catch (err) {
      console.error('Error creating admin:', err);
    } finally {
      await pool.end();
      process.exit(0);
    }
  });
});
