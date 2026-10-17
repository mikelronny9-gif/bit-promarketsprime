const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

const dataDir = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, 'broker.sqlite'));
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'client',
  balance REAL NOT NULL DEFAULT 10000,
  status TEXT NOT NULL DEFAULT 'active',
  kyc_status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);
const [name, email, password] = process.argv.slice(2);
if (!name || !email || !password || password.length < 16) {
  console.error('Usage: node create-admin.js "Platform Admin" "admin@example.com" "A-unique-password-at-least-16-chars"');
  process.exit(1);
}
const hash = bcrypt.hashSync(password, 12);
try {
  db.prepare(`INSERT INTO users (name,email,password_hash,role,balance,status,kyc_status)
              VALUES (?,?,?,'admin',0,'active','not_required')`).run(name, email.toLowerCase(), hash);
  console.log('Admin created. Keep the password private.');
} catch (e) {
  if (String(e.message).includes('UNIQUE')) console.error('That email already exists.');
  else console.error(e.message);
  process.exitCode = 1;
}
db.close();
