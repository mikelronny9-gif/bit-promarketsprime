const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');

const app = express();
const port = process.env.PORT || 3000;
const dataDir = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });
const dbPath = path.join(dataDir, 'broker.sqlite');
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'client', balance REAL NOT NULL DEFAULT 10000,
 status TEXT NOT NULL DEFAULT 'active', kyc_status TEXT NOT NULL DEFAULT 'pending',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS transactions (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, type TEXT NOT NULL,
 amount REAL NOT NULL, status TEXT NOT NULL DEFAULT 'pending', note TEXT DEFAULT '',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_log (
 id INTEGER PRIMARY KEY AUTOINCREMENT, admin_id INTEGER, action TEXT NOT NULL,
 details TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

app.set('trust proxy', 1);
app.use(express.json({ limit: '20kb' }));
app.use(express.urlencoded({ extended: false }));
app.use(session({
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: dataDir }),
  secret: process.env.SESSION_SECRET || 'development-only-change-this-secret-before-deploying',
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 86400000 }
}));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, limit: 30 }));
app.use(express.static(path.join(__dirname, 'public')));

const getUser = id => db.prepare('SELECT id,name,email,role,balance,status,kyc_status,created_at FROM users WHERE id=?').get(id);
const requireAuth = (req,res,next) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Please sign in first.' });
  const user = getUser(req.session.userId);
  if (!user || user.status !== 'active') return res.status(403).json({ error: 'Account unavailable.' });
  req.user = user; next();
};
const requireAdmin = (req,res,next) => req.user?.role === 'admin' ? next() : res.status(403).json({ error: 'Admin access required.' });
const audit = (adminId, action, details) => db.prepare('INSERT INTO audit_log (admin_id,action,details) VALUES (?,?,?)').run(adminId,action,details);

app.get('/api/health', (req,res) => res.json({ ok: true }));
app.post('/api/auth/register', (req,res) => {
  const name = String(req.body.name || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (name.length < 2 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 10)
    return res.status(400).json({ error: 'Enter a name, valid email, and password with at least 10 characters.' });
  try {
    const hash = bcrypt.hashSync(password, 12);
    const result = db.prepare('INSERT INTO users (name,email,password_hash) VALUES (?,?,?)').run(name,email,hash);
    req.session.userId = Number(result.lastInsertRowid);
    res.json({ user: getUser(req.session.userId) });
  } catch { res.status(409).json({ error: 'An account with that email may already exist.' }); }
});
app.post('/api/auth/login', (req,res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const row = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (!row || !bcrypt.compareSync(password,row.password_hash) || row.status !== 'active')
    return res.status(401).json({ error: 'Email or password is incorrect, or the account is unavailable.' });
  req.session.userId = row.id;
  res.json({ user: getUser(row.id) });
});
app.post('/api/auth/logout', (req,res) => req.session.destroy(() => res.json({ ok: true })));
app.get('/api/me', requireAuth, (req,res) => res.json({ user: req.user }));
app.get('/api/transactions', requireAuth, (req,res) => {
  const rows = db.prepare('SELECT id,type,amount,status,note,created_at FROM transactions WHERE user_id=? ORDER BY id DESC LIMIT 100').all(req.user.id);
  res.json({ transactions: rows });
});
app.post('/api/transactions', requireAuth, (req,res) => {
  const type = String(req.body.type || '');
  const amount = Number(req.body.amount);
  const note = String(req.body.note || '').slice(0,200);
  if (!['demo_deposit','demo_withdrawal'].includes(type) || !Number.isFinite(amount) || amount <= 0 || amount > 1000000)
    return res.status(400).json({ error: 'Enter a valid amount and transaction type.' });
  const result = db.prepare('INSERT INTO transactions (user_id,type,amount,note) VALUES (?,?,?,?)').run(req.user.id,type,amount,note);
  res.json({ id: Number(result.lastInsertRowid), status: 'pending', message: 'Demo request submitted for review.' });
});
app.get('/api/admin/users', requireAuth, requireAdmin, (req,res) => {
  res.json({ users: db.prepare('SELECT id,name,email,role,balance,status,kyc_status,created_at FROM users ORDER BY id DESC').all() });
});
app.post('/api/admin/users/:id/balance', requireAuth, requireAdmin, (req,res) => {
  const id = Number(req.params.id), delta = Number(req.body.delta), reason = String(req.body.reason || '').trim().slice(0,200);
  if (!Number.isInteger(id) || !Number.isFinite(delta) || delta === 0 || Math.abs(delta) > 1000000 || !reason)
    return res.status(400).json({ error: 'Provide a valid demo balance change and reason.' });
  const user = db.prepare('SELECT id,balance FROM users WHERE id=?').get(id);
  if (!user || user.balance + delta < 0) return res.status(400).json({ error: 'User not found or balance cannot go below zero.' });
  db.prepare('UPDATE users SET balance=? WHERE id=?').run(user.balance + delta,id);
  db.prepare('INSERT INTO transactions (user_id,type,amount,status,note) VALUES (?,?,?,?,?)')
    .run(id,delta > 0 ? 'demo_adjustment_credit' : 'demo_adjustment_debit',Math.abs(delta),'completed',reason);
  audit(req.user.id,'demo_balance_adjustment',`User ${id}: ${delta}; reason: ${reason}`);
  res.json({ user: getUser(id) });
});
app.post('/api/admin/users/:id/status', requireAuth, requireAdmin, (req,res) => {
  const id = Number(req.params.id), status = String(req.body.status || '');
  if (!Number.isInteger(id) || !['active','blocked'].includes(status)) return res.status(400).json({ error: 'Invalid status.' });
  db.prepare('UPDATE users SET status=? WHERE id=? AND role != ?').run(status,id,'admin');
  audit(req.user.id,'user_status_change',`User ${id}: ${status}`);
  res.json({ user: getUser(id) });
});
app.post('/api/admin/users/:id/kyc', requireAuth, requireAdmin, (req,res) => {
  const id = Number(req.params.id), status = String(req.body.status || '');
  if (!Number.isInteger(id) || !['pending','demo_approved','demo_declined'].includes(status)) return res.status(400).json({ error: 'Invalid demo status.' });
  db.prepare('UPDATE users SET kyc_status=? WHERE id=? AND role != ?').run(status,id,'admin');
  audit(req.user.id,'demo_kyc_status_change',`User ${id}: ${status}`);
  res.json({ user: getUser(id), note: 'Demo status only; no real identity verification is performed.' });
});
app.get('/api/admin/transactions', requireAuth, requireAdmin, (req,res) => {
  res.json({ transactions: db.prepare(`SELECT t.*,u.name,u.email FROM transactions t JOIN users u ON u.id=t.user_id ORDER BY t.id DESC LIMIT 200`).all() });
});
app.post('/api/admin/transactions/:id/review', requireAuth, requireAdmin, (req,res) => {
  const id = Number(req.params.id), status = String(req.body.status || '');
  if (!Number.isInteger(id) || !['approved','declined'].includes(status)) return res.status(400).json({ error: 'Invalid review status.' });
  const tx = db.prepare('SELECT * FROM transactions WHERE id=?').get(id);
  if (!tx || tx.status !== 'pending') return res.status(409).json({ error: 'Request not found or already reviewed.' });
  if (status === 'approved' && tx.type === 'demo_withdrawal') {
    const u = db.prepare('SELECT balance FROM users WHERE id=?').get(tx.user_id);
    if (!u || u.balance < tx.amount) return res.status(400).json({ error: 'Insufficient demo balance.' });
    db.prepare('UPDATE users SET balance=balance-? WHERE id=?').run(tx.amount,tx.user_id);
  }
  if (status === 'approved' && tx.type === 'demo_deposit')
    db.prepare('UPDATE users SET balance=balance+? WHERE id=?').run(tx.amount,tx.user_id);
  db.prepare('UPDATE transactions SET status=? WHERE id=?').run(status,id);
  audit(req.user.id,'demo_transaction_review',`Transaction ${id}: ${status}`);
  res.json({ ok: true });
});
app.get('/api/admin/audit', requireAuth, requireAdmin, (req,res) => {
  res.json({ entries: db.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT 200').all() });
});
app.get('*', (req,res) => res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(port, () => console.log(`Demo platform listening on ${port}`));
