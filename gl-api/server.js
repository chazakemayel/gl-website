// server.js — clean ESM build for Render/Neon

import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { Pool } from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

// ---- Fail fast if DB URL missing ----
if (!process.env.DATABASE_URL) {
  console.error('❌ Missing DATABASE_URL env var'); process.exit(1);
}

// ---- Config ----
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me';

// Neon needs SSL; URL already has sslmode=require, but add guard too
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const app = express();

// ---- JSON ----
app.use(express.json({ limit: '2mb' }));

// ---- CORS (robust; works with file:// and hosted pages) ----
app.use(cors({
  origin: (origin, cb) => cb(null, true), // allow all origins, incl. null
  credentials: true,
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','bypass-tunnel-reminder']
}));

// Explicit preflight handler
app.options('*', (req, res) => {
  res.set({
    'Access-Control-Allow-Origin': req.headers.origin || '*',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, bypass-tunnel-reminder'
  });
  res.sendStatus(204);
});

// ---- Helpers ----
function signToken(user) {
  return jwt.sign({ uid: user.id, email: user.email }, JWT_SECRET, { expiresIn: '10d' });
}
async function getUserByEmail(email) {
  const q = await pool.query('SELECT * FROM app_user WHERE email=$1 LIMIT 1', [email]);
  return q.rows[0] || null;
}
function authMiddleware(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).send('Missing token');
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).send('Invalid token'); }
}

// ---- Health ----
app.get('/api/health', (_req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

// ---- Auth ----
app.post('/api/auth/register', async (req, res) => {
  const { email, password, name } = req.body || {};
  if (!email || !password) return res.status(400).send('Email and password required');

  const exists = await getUserByEmail(email);
  if (exists) return res.status(409).send('Email already registered');

  const hash = await bcrypt.hash(password, 12);
  const q = await pool.query(
    `INSERT INTO app_user (email, password_hash, name)
     VALUES ($1,$2,$3)
     RETURNING id, email, name, created_at`,
    [email, hash, name || null]
  );
  const user = q.rows[0];
  const token = signToken(user);
  res.json({ token, user });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).send('Email and password required');

  const user = await getUserByEmail(email);
  if (!user) return res.status(401).send('Invalid credentials');

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).send('Invalid credentials');

  const token = signToken(user);
  res.json({
    token,
    user: { id: user.id, email: user.email, name: user.name, created_at: user.created_at }
  });
});

// ---- Password reset (email stub) ----
async function sendResetEmail(to, link) { console.log('RESET EMAIL to:', to, link); }

app.post('/api/auth/request-reset', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).send('Email required');

  const user = await getUserByEmail(email);
  if (!user) return res.json({ ok: true }); // don't leak

  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + 1000 * 60 * 30);
  await pool.query(
    `INSERT INTO password_reset (user_id, token, expires_at)
     VALUES ($1,$2,$3)`,
    [user.id, token, expires]
  );

  const base = process.env.PUBLIC_BASE_URL || `https://gl-website-6.onrender.com`;
  const link = `${base}/reset?token=${token}`;
  await sendResetEmail(email, link);
  res.json({ ok: true });
});

app.post('/api/auth/reset', async (req, res) => {
  const { token, newPassword } = req.body || {};
  if (!token || !newPassword) return res.status(400).send('Missing data');

  const q = await pool.query('SELECT * FROM password_reset WHERE token=$1 LIMIT 1', [token]);
  const row = q.rows[0];
  if (!row || row.used || new Date(row.expires_at) < new Date()) {
    return res.status(400).send('Invalid or expired token');
  }
  const hash = await bcrypt.hash(newPassword, 12);
  await pool.query('UPDATE app_user SET password_hash=$1 WHERE id=$2', [hash, row.user_id]);
  await pool.query('UPDATE password_reset SET used=true WHERE id=$1', [row.id]);
  res.json({ ok: true });
});

// ---- User-scoped audit data ----
app.post('/api/audits/:kind', authMiddleware, async (req, res) => {
  const { kind } = req.params;
  if (!['building','consumption','leaks','savings'].includes(kind)) {
    return res.status(400).send('Unknown kind');
  }
  await pool.query(`
    INSERT INTO audit_data (user_id, kind, payload)
    VALUES ($1,$2,$3)
    ON CONFLICT (user_id, kind)
    DO UPDATE SET payload = EXCLUDED.payload, updated_at = now()
  `, [req.user.uid, kind, req.body || {}]);
  res.json({ ok: true });
});

app.get('/api/audits/:kind', authMiddleware, async (req, res) => {
  const { kind } = req.params;
  const q = await pool.query(
    'SELECT payload FROM audit_data WHERE user_id=$1 AND kind=$2',
    [req.user.uid, kind]
  );
  res.json(q.rows[0]?.payload || {});
});

// ---- 404 & Error handlers ----
app.use((req, res) => res.status(404).json({ error: 'Not found' }));
app.use((err, _req, res, _next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Server error' });
});

// ---- Start ----
app.listen(PORT, () => console.log('API listening on', PORT));
