// RK Digital Solution - Backend API
// Run: npm install && npm start
// Deploy free on: Render.com / Railway.app / Cyclic.sh

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-key-in-production';

app.use(cors());
app.use(express.json());

// ── DATABASE SETUP ──────────────────────────────────────────
const db = new Database('rk_digital.db');

db.exec(`
CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY,
  name TEXT,
  mobile TEXT,
  password_hash TEXT,
  role TEXT DEFAULT 'Agent',
  balance REAL DEFAULT 0,
  commission REAL DEFAULT 0,
  todayTxn INTEGER DEFAULT 0,
  status TEXT DEFAULT 'active',
  kyc_status TEXT DEFAULT 'pending',
  shop_name TEXT,
  location TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS transactions (
  id TEXT PRIMARY KEY,
  agent_id TEXT,
  type TEXT,
  amount REAL,
  commission REAL,
  status TEXT,
  rrn TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY(agent_id) REFERENCES agents(id)
);

CREATE TABLE IF NOT EXISTS notices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT,
  message TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
`);

// Seed default admin if not exists
const adminExists = db.prepare('SELECT id FROM agents WHERE id = ?').get('RKADMIN');
if (!adminExists) {
  const hash = bcrypt.hashSync('admin@rk123', 10);
  db.prepare(`INSERT INTO agents (id, name, mobile, password_hash, role, status, kyc_status, shop_name, location)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run('RKADMIN', 'RK Admin', '9348356292', hash, 'Admin', 'active', 'verified', 'RK Digital Solution', 'Sonepur, Odisha');
  console.log('✅ Default admin created: RKADMIN / admin@rk123 (CHANGE THIS PASSWORD!)');
}

// ── AUTH MIDDLEWARE ──────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'Admin') return res.status(403).json({ error: 'Admin access required' });
  next();
}

// ── AUTH ROUTES ──────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { id, password } = req.body;
  if (!id || !password) return res.status(400).json({ error: 'ID and password required' });

  const agent = db.prepare('SELECT * FROM agents WHERE id = ?').get(id.toUpperCase());
  if (!agent) return res.status(401).json({ error: 'Invalid credentials' });
  if (agent.status === 'blocked') return res.status(403).json({ error: 'Account blocked. Contact admin.' });

  const valid = bcrypt.compareSync(password, agent.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ id: agent.id, role: agent.role }, JWT_SECRET, { expiresIn: '7d' });
  delete agent.password_hash;
  res.json({ token, agent });
});

app.post('/api/register', (req, res) => {
  const { id, name, mobile, password, shop_name, location } = req.body;
  if (!id || !name || !mobile || !password) return res.status(400).json({ error: 'Missing required fields' });

  const existing = db.prepare('SELECT id FROM agents WHERE id = ?').get(id.toUpperCase());
  if (existing) return res.status(409).json({ error: 'Agent ID already exists' });

  const hash = bcrypt.hashSync(password, 10);
  db.prepare(`INSERT INTO agents (id, name, mobile, password_hash, shop_name, location)
    VALUES (?, ?, ?, ?, ?, ?)`)
    .run(id.toUpperCase(), name, mobile, hash, shop_name || '', location || '');

  res.json({ success: true, message: 'Agent registered. Awaiting KYC verification.' });
});

// ── AGENT PROFILE ────────────────────────────────────────────
app.get('/api/profile', authMiddleware, (req, res) => {
  const agent = db.prepare('SELECT id,name,mobile,role,balance,commission,todayTxn,status,kyc_status,shop_name,location,created_at FROM agents WHERE id = ?').get(req.user.id);
  res.json(agent);
});

app.post('/api/change-password', authMiddleware, (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const agent = db.prepare('SELECT password_hash FROM agents WHERE id = ?').get(req.user.id);
  if (!bcrypt.compareSync(oldPassword, agent.password_hash)) {
    return res.status(401).json({ error: 'Old password incorrect' });
  }
  const newHash = bcrypt.hashSync(newPassword, 10);
  db.prepare('UPDATE agents SET password_hash = ? WHERE id = ?').run(newHash, req.user.id);
  res.json({ success: true });
});

// ── TRANSACTIONS ─────────────────────────────────────────────
app.post('/api/transactions', authMiddleware, (req, res) => {
  const { type, amount, commission, status, rrn } = req.body;
  const id = 'TXN' + Date.now();

  db.prepare(`INSERT INTO transactions (id, agent_id, type, amount, commission, status, rrn)
    VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run(id, req.user.id, type, amount, commission, status, rrn || '');

  if (status === 'success') {
    db.prepare(`UPDATE agents SET balance = balance - ?, commission = commission + ?, todayTxn = todayTxn + 1 WHERE id = ?`)
      .run(amount, commission, req.user.id);
  }
  res.json({ success: true, id });
});

app.get('/api/transactions', authMiddleware, (req, res) => {
  const rows = req.user.role === 'Admin'
    ? db.prepare('SELECT * FROM transactions ORDER BY created_at DESC LIMIT 100').all()
    : db.prepare('SELECT * FROM transactions WHERE agent_id = ? ORDER BY created_at DESC LIMIT 100').all(req.user.id);
  res.json(rows);
});

// ── ADMIN ROUTES ─────────────────────────────────────────────
app.get('/api/admin/agents', authMiddleware, adminOnly, (req, res) => {
  const rows = db.prepare('SELECT id,name,mobile,role,balance,commission,todayTxn,status,kyc_status,shop_name,location,created_at FROM agents').all();
  res.json(rows);
});

app.post('/api/admin/agents/:id/wallet', authMiddleware, adminOnly, (req, res) => {
  const { amount, action } = req.body; // action: 'add' or 'deduct'
  const delta = action === 'add' ? amount : -amount;
  db.prepare('UPDATE agents SET balance = balance + ? WHERE id = ?').run(delta, req.params.id);
  res.json({ success: true });
});

app.post('/api/admin/agents/:id/status', authMiddleware, adminOnly, (req, res) => {
  const { status } = req.body; // 'active' or 'blocked'
  db.prepare('UPDATE agents SET status = ? WHERE id = ?').run(status, req.params.id);
  res.json({ success: true });
});

app.post('/api/admin/notices', authMiddleware, adminOnly, (req, res) => {
  const { title, message } = req.body;
  db.prepare('INSERT INTO notices (title, message) VALUES (?, ?)').run(title, message);
  res.json({ success: true });
});

app.get('/api/notices', (req, res) => {
  const rows = db.prepare('SELECT * FROM notices ORDER BY created_at DESC LIMIT 10').all();
  res.json(rows);
});

// ── HEALTH CHECK ─────────────────────────────────────────────
app.get('/api/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

app.listen(PORT, () => console.log(`🚀 RK Digital Backend running on port ${PORT}`));
