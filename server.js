// server.js — Water Audit Platform (ESM)
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { Pool } from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import nodemailer from 'nodemailer';

// ===== Env =====
const {
  PORT = 8080,
  JWT_SECRET = 'change-me',
  DATABASE_URL,
  FRONTEND_ORIGIN = 'https://grleaders.org',
  FRONTEND_RESET_URL = 'https://grleaders.org/WaterAudit%20-%20Reset%20Password.html',
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, EMAIL_FROM = 'Green Leaders <noreply@example.com>'
} = process.env;

if (!DATABASE_URL) {
  console.error('❌ Missing DATABASE_URL in .env');
  process.exit(1);
}

// ===== DB =====
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Create tables if not exists
await pool.query(`
  CREATE TABLE IF NOT EXISTS app_user (
    id                 BIGSERIAL PRIMARY KEY,
    email              TEXT UNIQUE NOT NULL,
    name               TEXT,
    password_hash      TEXT,
    building_name      TEXT,
    building_location  TEXT,
    email_verified     BOOLEAN DEFAULT FALSE,
    otp_code           TEXT,
    otp_expires        TIMESTAMP WITH TIME ZONE,
    reset_token_hash   TEXT,
    reset_token_expires TIMESTAMP WITH TIME ZONE,
    token_version      INTEGER DEFAULT 0,
    created_at         TIMESTAMP WITH TIME ZONE DEFAULT now()
  );

  CREATE TABLE IF NOT EXISTS audit_data (
    user_id   BIGINT REFERENCES app_user(id) ON DELETE CASCADE,
    kind      TEXT NOT NULL,
    payload   JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    PRIMARY KEY (user_id, kind)
  );
`);

// ===== Mailer =====
const mailer = nodemailer.createTransport({
  host: SMTP_HOST,
  port: Number(SMTP_PORT || 587),
  secure: false,
  auth: (SMTP_USER && SMTP_PASS) ? { user: SMTP_USER, pass: SMTP_PASS } : undefined
});

// ===== Utils =====
const normEmail = e => (e || '').trim().toLowerCase();
const sixDigit = () => String(Math.floor(100000 + Math.random() * 900000));
const signToken = user => jwt.sign({ uid: user.id, email: user.email, ver: user.token_version || 0 }, JWT_SECRET, { expiresIn: '10d' });

async function getUserByEmail(email) {
  const q = await pool.query('SELECT * FROM app_user WHERE LOWER(email)=LOWER($1) LIMIT 1', [email]);
  return q.rows[0] || null;
}
async function sendOtpEmail(to, code) {
  const html = `
    <div style="font-family:Inter,Arial">
      <h2>Verify your email</h2>
      <p>Your verification code:</p>
      <div style="font-size:22px;font-weight:800;letter-spacing:3px">${code}</div>
      <p>This code expires in 10 minutes.</p>
    </div>`;
  await mailer.sendMail({ from: EMAIL_FROM, to, subject: 'Verify your email – Water Audit', html });
}
async function sendResetEmail(to, rawToken) {
  const link = `${FRONTEND_RESET_URL}?token=${encodeURIComponent(rawToken)}`;
  const html = `
    <div style="font-family:Inter,Arial">
      <h2>Reset your password</h2>
      <p>Click below to reset your password (expires in 15 minutes):</p>
      <p><a href="${link}" style="display:inline-block;padding:10px 14px;background:#00a651;color:#fff;border-radius:8px;text-decoration:none">Reset Password</a></p>
      <p>If the button doesn’t work, copy/paste this URL:<br>${link}</p>
    </div>`;
  await mailer.sendMail({ from: EMAIL_FROM, to, subject: 'Reset your password – Water Audit', html });
}

// ===== App =====
const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(cors({
  origin(origin, cb) {
    const allowed = (FRONTEND_ORIGIN || '').split(',').map(s=>s.trim());
    const ok = !origin || allowed.includes(origin);
    cb(null, ok ? origin : false);
  },
  credentials: true,
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','bypass-tunnel-reminder']
}));
app.options('*', (req,res) => {
  res.set({
    'Access-Control-Allow-Origin': req.headers.origin || '*',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, bypass-tunnel-reminder'
  });
  res.sendStatus(204);
});

// Health
app.get('/api/health', (_req,res)=>res.json({ ok:true, time:new Date().toISOString() }));

// ===== AUTH =====

// 1) Send OTP
app.post('/api/auth/send-otp', async (req,res)=>{
  const email = normEmail(req.body?.email);
  if(!email) return res.status(400).send('Email required');

  const code = sixDigit();
  const expires = new Date(Date.now() + 10*60*1000);

  let user = await getUserByEmail(email);
  if(!user){
    const q = await pool.query(
      `INSERT INTO app_user (email, email_verified, otp_code, otp_expires)
       VALUES ($1,false,$2,$3) RETURNING *`,
      [email, code, expires]
    );
    user = q.rows[0];
  }else{
    await pool.query(`UPDATE app_user SET otp_code=$2, otp_expires=$3 WHERE id=$1`,[user.id, code, expires]);
  }
  await sendOtpEmail(email, code);
  res.json({ ok:true });
});

// 2) Register with OTP
app.post('/api/auth/register-with-otp', async (req,res)=>{
  const { name, email, password, buildingName, buildingLocation, code } = req.body || {};
  const e = normEmail(email);
  if(!name || !e || !password || !buildingName || !buildingLocation || !code)
    return res.status(400).send('Missing required fields');

  const user = await getUserByEmail(e);
  if(!user || !user.otp_code || !user.otp_expires) return res.status(400).send('Request a verification code first');
  if(new Date(user.otp_expires) < new Date() || user.otp_code !== code) return res.status(400).send('Invalid or expired verification code');
  if(user.password_hash) return res.status(409).send('Email already registered');

  const hash = await bcrypt.hash(password, 12);
  const q = await pool.query(
    `UPDATE app_user
       SET name=$2, password_hash=$3, building_name=$4, building_location=$5,
           email_verified=true, otp_code=NULL, otp_expires=NULL
     WHERE id=$1 RETURNING *`,
    [user.id, name, hash, buildingName, buildingLocation]
  );
  const saved = q.rows[0];
  const token = signToken(saved);
  res.json({ token, user:{
    id:saved.id, email:saved.email, name:saved.name,
    buildingName:saved.building_name, buildingLocation:saved.building_location
  }});
});

// 3) Resend verification
app.post('/api/auth/resend-verification', async (req,res)=>{
  const email = normEmail(req.body?.email);
  if(!email) return res.status(400).send('Email required');
  const user = await getUserByEmail(email);
  if(!user) return res.status(404).send('No account found');
  if(user.email_verified) return res.json({ ok:true });

  const code = sixDigit();
  await pool.query(`UPDATE app_user SET otp_code=$2, otp_expires=$3 WHERE id=$1`, [user.id, code, new Date(Date.now()+10*60*1000)]);
  await sendOtpEmail(email, code);
  res.json({ ok:true });
});

// 4) Login
app.post('/api/auth/login', async (req,res)=>{
  const email = normEmail(req.body?.email);
  const { password } = req.body || {};
  if(!email || !password) return res.status(400).send('Email and password required');

  const user = await getUserByEmail(email);
  if(!user || !user.password_hash) return res.status(401).send('Invalid credentials');

  const ok = await bcrypt.compare(password, user.password_hash);
  if(!ok) return res.status(401).send('Invalid credentials');
  if(!user.email_verified) return res.status(403).send('email_not_verified');

  const token = signToken(user);
  res.json({ token, user:{
    id:user.id, email:user.email, name:user.name,
    buildingName:user.building_name, buildingLocation:user.building_location
  }});
});

// 5) Forgot password
app.post('/api/auth/forgot-password', async (req,res)=>{
  const email = normEmail(req.body?.email);
  // Always return 200 for privacy
  const user = email ? await getUserByEmail(email) : null;
  if(user){
    const raw = crypto.randomBytes(32).toString('hex');
    const hash = crypto.createHash('sha256').update(raw).digest('hex');
    await pool.query(`UPDATE app_user SET reset_token_hash=$2, reset_token_expires=$3 WHERE id=$1`, [user.id, hash, new Date(Date.now()+15*60*1000)]);
    await sendResetEmail(user.email, raw);
  }
  res.json({ ok:true });
});

// 6) Reset password
app.post('/api/auth/reset-password', async (req,res)=>{
  const { token, newPassword } = req.body || {};
  if(!token || !newPassword) return res.status(400).send('Missing token or password');
  const hash = crypto.createHash('sha256').update(token).digest('hex');

  const q = await pool.query(
    `SELECT * FROM app_user WHERE reset_token_hash=$1 AND reset_token_expires > now() LIMIT 1`,
    [hash]
  );
  const user = q.rows[0];
  if(!user) return res.status(400).send('Invalid or expired token');

  const pw = await bcrypt.hash(newPassword, 12);
  await pool.query(
    `UPDATE app_user SET password_hash=$2, reset_token_hash=NULL, reset_token_expires=NULL, token_version=COALESCE(token_version,0)+1 WHERE id=$1`,
    [user.id, pw]
  );
  res.json({ ok:true });
});

// ===== Auth middleware =====
function auth(req,res,next){
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if(!token) return res.status(401).send('Missing token');
  try{ req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch{ return res.status(401).send('Invalid token'); }
}

// ===== Audits =====
app.post('/api/audits/:kind', auth, async (req,res)=>{
  const { kind } = req.params;
  if(!['building','consumption','leaks','savings'].includes(kind)) return res.status(400).send('Unknown kind');
  await pool.query(`
    INSERT INTO audit_data (user_id, kind, payload, updated_at)
    VALUES ($1,$2,$3,now())
    ON CONFLICT (user_id, kind) DO UPDATE SET payload=EXCLUDED.payload, updated_at=now()
  `, [req.user.uid, kind, req.body || {}]);
  res.json({ ok:true });
});
app.get('/api/audits/:kind', auth, async (req,res)=>{
  const { kind } = req.params;
  const q = await pool.query(`SELECT payload FROM audit_data WHERE user_id=$1 AND kind=$2`, [req.user.uid, kind]);
  res.json(q.rows[0]?.payload || {});
});

// 404 + error
app.use((req,res)=>res.status(404).json({error:'Not found'}));
app.use((err,_req,res,_next)=>{ console.error(err); res.status(500).json({error:'Server error'}); });

app.listen(PORT, ()=>console.log(`✅ API listening on :${PORT}`));
// ===== Audits =====
app.post('/api/audits/:kind', auth, async (req, res) => {
  const { kind } = req.params;
  if (!['building', 'consumption', 'leaks', 'savings'].includes(kind))
    return res.status(400).send('Unknown kind');

  await pool.query(`
    INSERT INTO audit_data (user_id, kind, payload, updated_at)
    VALUES ($1,$2,$3,now())
    ON CONFLICT (user_id, kind)
    DO UPDATE SET payload=EXCLUDED.payload, updated_at=now()
  `, [req.user.uid, kind, req.body || {}]);

  res.json({ ok: true });
});

app.get('/api/audits/:kind', auth, async (req, res) => {
  const { kind } = req.params;
  const q = await pool.query(
    `SELECT payload FROM audit_data WHERE user_id=$1 AND kind=$2`,
    [req.user.uid, kind]
  );
  res.json(q.rows[0]?.payload || {});
});
