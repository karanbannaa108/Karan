// createAdmin.js — run one time to create admin
require('dotenv').config();
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');
const readline = require('readline');

const DB_FILE = path.join(__dirname, 'database.sqlite');
const db = new sqlite3.Database(DB_FILE);

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

rl.question('Admin username: ', (username) => {
  rl.question('Admin password (will be hashed): ', async (password) => {
    const hash = await bcrypt.hash(password, 12);
    const id = 'u_' + (Math.random().toString(36).slice(2,9));
    const created_at = Date.now();
    db.run('INSERT INTO users(id,name,password_hash,role,created_at) VALUES(?,?,?,?,?)',
      [id, username, hash, 'admin', created_at],
      function (err) {
        if (err) {
          console.error('Error creating admin (maybe user exists):', err);
        } else {
          console.log('Admin created with id', id);
        }
        db.close();
        rl.close();
      });
  });
});
