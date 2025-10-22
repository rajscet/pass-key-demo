import 'dotenv/config';
import path from 'node:path';
import express from 'express';
import cors from 'cors';
import { supabase, ensureProfile } from './supabase.js';
import { signAppJWT, authMiddleware } from './jwt.js';
import { startRegistration, finishRegistration, startAuthentication, finishAuthentication } from './webauthn.js';

const app = express();
app.use(express.static('public'));
app.use(express.json({ limit: '1mb' }));

app.use('/.well-known', express.static(path.join(process.cwd(), 'well-known'), { dotfiles: 'allow' }));

const CORS_ORIGINS = (process.env.CORS_ORIGINS || '').split(',').filter(Boolean);
console.log('CORS_ORIGINS', CORS_ORIGINS);
app.use(cors({ origin: (origin, cb) => cb(null, !origin || CORS_ORIGINS.includes(origin)), credentials: true }));

app.get('/health', (req, res) => res.json({ ok: true }));

app.post('/auth/request-otp', async (req, res) => {
  try {
    const { phone } = req.body || {};
    if (!phone) return res.status(400).json({ error: 'phone required' });
    const { error } = await supabase.auth.signInWithOtp({ phone, options: { channel: 'sms' } });
    if (error) return res.status(400).json({ error: error.message, code: error.code });
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

app.post('/auth/verify-otp', async (req, res) => {
  try {
    const { phone, token } = req.body || {};
    if (!phone || !token) return res.status(400).json({ error: 'phone & token required' });

    const { data, error } = await supabase.auth.verifyOtp({ phone, token, type: 'sms' });
    if (error) {
      console.error('verify-otp supabase error', error);
      return res.status(400).json({ error: error.message, code: error.code });
    }

    const user = data?.user;
    if (!user) return res.status(400).json({ error: 'Invalid or expired OTP' });

    let profile;
    try { profile = await ensureProfile({ userId: user.id, phone }); }
    catch (e) { console.error('ensureProfile failed', e); return res.status(500).json({ error: 'Profile creation failed' }); }

    const appToken = signAppJWT({ sub: profile.id, phone: profile.phone || phone });
    return res.json({ token: appToken, user: { id: profile.id, phone: profile.phone || phone } });
  } catch (e) {
    console.error('verify-otp unhandled', e);
    return res.status(500).json({ error: e.message });
  }
});

app.post('/passkey/register/start', authMiddleware, async (req, res) => {
  try {
    const user = { id: req.user.sub, phone: req.user.phone };
    const options = await startRegistration(user);
    res.json(options);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/passkey/register/finish', authMiddleware, async (req, res) => {
  try {
    const user = { id: req.user.sub, phone: req.user.phone };
    const { credential } = req.body;
    const result = await finishRegistration(user, credential);
    if (!result.verified) return res.status(400).json({ error: 'Registration not verified' });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/passkey/login/start', async (req, res) => {
  try {
    const { phone } = req.body || {};
    if (!phone) return res.status(400).json({ error: 'phone required' });
    const { data: profile } = await supabase.from('profiles').select('*').eq('phone', phone).maybeSingle();
    if (!profile) return res.status(404).json({ error: 'No user with this phone' });
    const options = await startAuthentication({ id: profile.id, phone: profile.phone });
    res.json({ options, userId: profile.id });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/passkey/login/finish', async (req, res) => {
  try {
    const { userId, assertion } = req.body || {};
    if (!userId || !assertion) return res.status(400).json({ error: 'userId & assertion required' });

    console.log('login/finish called for userId', userId);

    const credIds = [assertion.id, assertion.rawId].filter(Boolean);
    if (!credIds.length) return res.status(400).json({ error: 'Missing assertion.id/rawId' });

    const table = process.env.CREDENTIALS_TABLE || 'passkey_credentials';
    const { data: rows, error: findErr } = await supabase
      .from(table)
      .select('*')
      .eq('user_id', userId)
      .in('credential_id', credIds)
      .order('created_at', { ascending: false })
      .limit(1);
console.log('A', 'A');
    if (findErr) {
      console.error('login/finish DB lookup error', findErr);
      return res.status(500).json({ error: 'DB lookup failed', details: findErr.message });
    }
    const cred = rows?.[0];
    if (!cred) return res.status(404).json({ error: 'Credential not found for user', idsTried: credIds });
console.log('login/finish called for userId', userId);
    const result = await finishAuthentication({ id: userId, cred }, assertion);
    if (!result.verified) {
      return res.status(401).json({ error: 'Authentication failed', reason: result.reason || result.error || 'unverified', details: result.details });
    }
    console.log('Result', result);
    const { data: profile } = await supabase.from('profiles').select('*').eq('id', userId).single();
    const appToken = signAppJWT({ sub: profile.id, phone: profile.phone });
    console.log('appToken', appToken);
    return res.json({ token: appToken, user: { id: profile.id, phone: profile.phone } });
  } catch (e) {
    console.error('login/finish unhandled', e);
    return res.status(500).json({ error: e.message || 'Login error' });
  }
});

app.get('/me', authMiddleware, async (req, res) => {
  const { sub } = req.user;
  const { data: profile } = await supabase.from('profiles').select('*').eq('id', sub).single();
  res.json({ user: profile });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Auth server on http://localhost:${PORT}`));
