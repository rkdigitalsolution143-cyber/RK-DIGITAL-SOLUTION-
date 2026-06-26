// RK Digital Solution - Backend v4.0
// Supabase (Free PostgreSQL) + Vercel (Free Hosting)
// No card required!

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'rkdigital2026secretkey9348356292';
const FAST2SMS_KEY = process.env.FAST2SMS_API_KEY || 'F8bKrpUskYyvUtwQPyc9MFB6vomFQDhrWWtSbMJrslnyvqK1M9PYYsxdEGb0';
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://keehqhyzztphsgzscwvu.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_KEY || 'sb_publishable_t27VjWwYoipKAp0fCkkzSg_zS3oeco4';

// ── SUPABASE DB HELPER ────────────────────────────────────────
async function dbQuery(endpoint, method = 'GET', body = null, headers = {}) {
  const url = `${SUPABASE_URL}/rest/v1/${endpoint}`;
  const res = await fetch(url, {
    method,
    headers: {
      'apikey': SUPABASE_KEY,
      'Authorization': `Bearer ${SUPABASE_KEY}`,
      'Content-Type': 'application/json',
      'Prefer': method === 'POST' ? 'return=representation' : 'return=minimal',
      ...headers
    },
    body: body ? JSON.stringify(body) : null
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`DB Error: ${err}`);
  }
  const text = await res.text();
  return text ? JSON.parse(text) : null;
}

// ── RATE LIMITING ─────────────────────────────────────────────
const rateLimitMap = new Map();
function rateLimit(maxRequests, windowMs) {
  return (req, res, next) => {
    const key = (req.ip || 'unknown') + req.path;
    const now = Date.now();
    const windowStart = now - windowMs;
    if (!rateLimitMap.has(key)) rateLimitMap.set(key, []);
    const requests = rateLimitMap.get(key).filter(t => t > windowStart);
    if (requests.length >= maxRequests) {
      return res.status(429).json({ error: 'Too many requests. Please wait.' });
    }
    requests.push(now);
    rateLimitMap.set(key, requests);
    next();
  };
}

function sanitize(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[<>'"`;]/g, '').trim().substring(0, 500);
}

// ── MIDDLEWARE ────────────────────────────────────────────────
app.use(cors({
  origin: [/\.netlify\.app$/, 'http://localhost:3000'],
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization']
}));
app.use(express.json({ limit: '1mb' }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});

// ── AUTH MIDDLEWARE ───────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch(e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}
function adminOnly(req, res, next) {
  if (req.user.role !== 'Admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// ── OTP STORE (in-memory, 2 min expiry) ─────────────────────
const otpStore = new Map();

// ── AUTH ROUTES ───────────────────────────────────────────────

// Login Step 1: Password verify → Send OTP
app.post('/api/login', rateLimit(5, 60000), async (req, res) => {
  try {
    const id = sanitize(req.body.id || '').toUpperCase();
    const password = req.body.password || '';
    if (!id || !password) return res.status(400).json({ error: 'Required fields missing' });

    const agents = await dbQuery(`agents?id=eq.${id}&select=*`);
    const agent = agents && agents[0];

    if (!agent) return res.status(401).json({ error: 'Invalid credentials' });
    if (agent.status === 'blocked') return res.status(403).json({ error: 'Account blocked' });
    if (agent.login_attempts >= 5) return res.status(429).json({ error: 'Too many attempts. Contact admin.' });

    const valid = bcrypt.compareSync(password, agent.password_hash);
    if (!valid) {
      await dbQuery(`agents?id=eq.${id}`, 'PATCH', { login_attempts: (agent.login_attempts || 0) + 1 });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Reset attempts + generate OTP
    await dbQuery(`agents?id=eq.${id}`, 'PATCH', { login_attempts: 0, last_login: new Date().toISOString() });
    const otp = Math.floor(1000 + Math.random() * 9000).toString();
    otpStore.set(id, { otp, expires: Date.now() + 120000, attempts: 0, mobile: agent.mobile });

    // Send OTP via Fast2SMS
    try {
      await fetch('https://www.fast2sms.com/dev/bulkV2', {
        method: 'POST',
        headers: { 'authorization': FAST2SMS_KEY, 'Content-Type': 'application/json' },
        body: JSON.stringify({ route: 'otp', variables_values: otp, numbers: agent.mobile })
      });
    } catch(e) { console.log('SMS error:', e.message); }

    res.json({ success: true, mobile: agent.mobile.slice(0,2) + '******' + agent.mobile.slice(-2) });
  } catch(e) {
    console.error('Login error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login Step 2: Verify OTP → Return JWT
app.post('/api/verify-otp', rateLimit(10, 60000), async (req, res) => {
  try {
    const id = sanitize(req.body.id || '').toUpperCase();
    const otp = sanitize(req.body.otp || '');
    const record = otpStore.get(id);

    if (!record) return res.status(400).json({ error: 'OTP expired. Login again.' });
    if (Date.now() > record.expires) { otpStore.delete(id); return res.status(400).json({ error: 'OTP expired.' }); }
    if (record.attempts >= 3) { otpStore.delete(id); return res.status(429).json({ error: 'Too many wrong OTPs.' }); }
    if (record.otp !== otp) {
      record.attempts++;
      return res.status(401).json({ error: 'Wrong OTP.' });
    }

    otpStore.delete(id);
    const agents = await dbQuery(`agents?id=eq.${id}&select=id,name,mobile,role,balance,commission,today_txn,status,kyc_status,shop_name,location`);
    const agent = agents[0];
    const token = jwt.sign({ id: agent.id, role: agent.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, agent });
  } catch(e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Register
app.post('/api/register', rateLimit(3, 60000), async (req, res) => {
  try {
    const id = sanitize(req.body.id || '').toUpperCase();
    const name = sanitize(req.body.name || '');
    const mobile = sanitize(req.body.mobile || '');
    const password = req.body.password || '';
    if (!id || !name || !mobile || !password) return res.status(400).json({ error: 'Missing fields' });
    if (password.length < 6) return res.status(400).json({ error: 'Password min 6 chars' });

    const existing = await dbQuery(`agents?id=eq.${id}`);
    if (existing && existing.length > 0) return res.status(409).json({ error: 'Agent ID exists' });

    const hash = bcrypt.hashSync(password, 12);
    await dbQuery('agents', 'POST', {
      id, name, mobile, password_hash: hash,
      shop_name: sanitize(req.body.shop_name || ''),
      location: sanitize(req.body.location || ''),
      role: 'Agent', status: 'active', balance: 0, commission: 0, today_txn: 0,
      kyc_status: 'pending', login_attempts: 0
    });
    res.json({ success: true });
  } catch(e) {
    res.status(500).json({ error: 'Server error: ' + e.message });
  }
});

// ── PROFILE ───────────────────────────────────────────────────
app.get('/api/profile', authMiddleware, async (req, res) => {
  try {
    const agents = await dbQuery(`agents?id=eq.${req.user.id}&select=id,name,mobile,role,balance,commission,today_txn,status,kyc_status,shop_name,location,last_login,created_at`);
    res.json(agents[0]);
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/change-password', authMiddleware, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword || newPassword.length < 6) return res.status(400).json({ error: 'Invalid input' });
    const agents = await dbQuery(`agents?id=eq.${req.user.id}&select=password_hash`);
    if (!bcrypt.compareSync(oldPassword, agents[0].password_hash)) return res.status(401).json({ error: 'Wrong old password' });
    await dbQuery(`agents?id=eq.${req.user.id}`, 'PATCH', { password_hash: bcrypt.hashSync(newPassword, 12) });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ── TRANSACTIONS ──────────────────────────────────────────────
app.post('/api/transactions', authMiddleware, rateLimit(30, 60000), async (req, res) => {
  try {
    const { type, amount, commission, status, rrn } = req.body;
    const amt = parseFloat(amount);
    const comm = parseFloat(commission) || 0;
    if (!type || !amt || amt <= 0 || amt > 50000) return res.status(400).json({ error: 'Invalid data' });

    const id = 'TXN' + Date.now() + Math.random().toString(36).substring(2, 5).toUpperCase();
    await dbQuery('transactions', 'POST', {
      id, agent_id: req.user.id, type: sanitize(type),
      amount: amt, commission: comm,
      status: sanitize(status || 'success'), rrn: sanitize(rrn || ''),
      created_at: new Date().toISOString()
    });

    if (status === 'success') {
      const agents = await dbQuery(`agents?id=eq.${req.user.id}&select=balance,commission,today_txn`);
      const ag = agents[0];
      await dbQuery(`agents?id=eq.${req.user.id}`, 'PATCH', {
        balance: (ag.balance || 0) - amt,
        commission: (ag.commission || 0) + comm,
        today_txn: (ag.today_txn || 0) + 1
      });
    }
    res.json({ success: true, id });
  } catch(e) { res.status(500).json({ error: 'Server error: ' + e.message }); }
});

app.get('/api/transactions', authMiddleware, async (req, res) => {
  try {
    const filter = req.user.role === 'Admin' ? '' : `&agent_id=eq.${req.user.id}`;
    const rows = await dbQuery(`transactions?order=created_at.desc&limit=100${filter}`);
    res.json(rows || []);
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ── OTP SEND ──────────────────────────────────────────────────
app.post('/api/send-otp', rateLimit(5, 60000), async (req, res) => {
  const { mobile, otp } = req.body;
  if (!mobile || !otp || !/^\d{10}$/.test(mobile.toString())) return res.status(400).json({ success: false });
  try {
    const response = await fetch('https://www.fast2sms.com/dev/bulkV2', {
      method: 'POST',
      headers: { 'authorization': FAST2SMS_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({ route: 'otp', variables_values: otp.toString(), numbers: mobile.toString() })
    });
    const data = await response.json();
    res.json({ success: data.return === true });
  } catch(e) { res.status(500).json({ success: false }); }
});

// ── ADMIN ─────────────────────────────────────────────────────
app.get('/api/admin/agents', authMiddleware, adminOnly, async (req, res) => {
  try {
    const rows = await dbQuery('agents?select=id,name,mobile,role,balance,commission,today_txn,status,kyc_status,shop_name,location,last_login,created_at');
    res.json(rows || []);
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/admin/agents/:id/wallet', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { amount, action } = req.body;
    const amt = parseFloat(amount);
    const agents = await dbQuery(`agents?id=eq.${req.params.id}&select=balance`);
    const currentBalance = agents[0].balance || 0;
    const newBalance = action === 'add' ? currentBalance + amt : currentBalance - amt;
    await dbQuery(`agents?id=eq.${req.params.id}`, 'PATCH', { balance: newBalance });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/admin/agents/:id/status', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { status } = req.body;
    await dbQuery(`agents?id=eq.${req.params.id}`, 'PATCH', { status, login_attempts: 0 });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/admin/agents/:id/kyc', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { kyc_status } = req.body;
    await dbQuery(`agents?id=eq.${req.params.id}`, 'PATCH', { kyc_status });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/admin/notices', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { title, message } = req.body;
    await dbQuery('notices', 'POST', { title: sanitize(title), message: sanitize(message), created_at: new Date().toISOString() });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/notices', async (req, res) => {
  try {
    const rows = await dbQuery('notices?order=created_at.desc&limit=10');
    res.json(rows || []);
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ── HEALTH ────────────────────────────────────────────────────
app.get('/api/health', async (req, res) => {
  try {
    const agents = await dbQuery('agents?select=id&limit=1');
    res.json({ status: 'ok', time: new Date().toISOString(), version: '4.0-supabase', db: 'connected' });
  } catch(e) {
    res.json({ status: 'ok', time: new Date().toISOString(), version: '4.0-supabase', db: 'error: ' + e.message });
  }
});

app.use((req, res) => res.status(404).json({ error: 'Not found' }));
app.use((err, req, res, next) => { res.status(500).json({ error: 'Server error' }); });

app.listen(PORT, () => console.log(`🚀 RK Digital v4.0 (Supabase) on port ${PORT}`));
  
