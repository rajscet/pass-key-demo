import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { supabase } from './supabase.js';

const { RP_ID, RP_NAME, RP_ORIGINS } = process.env;
const origins = (RP_ORIGINS || '').split(',').filter(Boolean);
console.log('CORS_ORIGINS', origins);
const RP_ID_HOST = (RP_ID || '').replace(/^https?:\/\//, '').replace(/\/.*/, '');
const CREDENTIALS_TABLE = process.env.CREDENTIALS_TABLE || 'passkey_credentials';

function uuidToBase64Url(uuid) {
  const hex = String(uuid).replace(/-/g, '').toLowerCase();
  if (hex.length !== 32) return Buffer.from(String(uuid), 'utf8').toString('base64url');
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return Buffer.from(bytes).toString('base64url');
}

function toB64Url(val) {
  if (typeof val === 'string') return val;
  return Buffer.from(val).toString('base64url');
}

function normalizePublicKey(pk) {
  // Shape logging
  try {
    const kind = Buffer.isBuffer(pk) ? 'Buffer'
      : (typeof pk === 'string' ? 'string'
      : (pk && typeof pk === 'object' && pk.byteLength ? 'TypedArray'
      : (pk && typeof pk === 'object' && Array.isArray(pk.data) ? 'BufferJSON'
      : typeof pk)));
    const sample = typeof pk === 'string'
      ? pk.slice(0, 20)
      : Buffer.isBuffer(pk)
        ? pk.slice(0, 8).toString('hex')
        : (pk && pk.byteLength ? Buffer.from(pk).slice(0,8).toString('hex') : '');
    console.log('🔎 pk kind =', kind, ' sample =', sample);
  } catch {}

  if (!pk) return Buffer.alloc(0);

  // Helper: convert object with numeric keys {"0":165,"1":1,...} to Uint8Array
  const fromNumericKeyedObject = (obj) => {
    const keys = Object.keys(obj).filter(k => /^\d+$/.test(k)).sort((a,b)=>Number(a)-Number(b));
    if (!keys.length) return null;
    const arr = new Uint8Array(keys.length);
    for (let i=0;i<keys.length;i++) arr[i] = Number(obj[keys[i]]) & 0xff;
    return arr;
  };

  // 1) If Supabase returned { data: [...] }
  if (pk && typeof pk === 'object' && Array.isArray(pk.data)) {
    return Buffer.from(Uint8Array.from(pk.data));
  }

  // 2) Node Buffer; might actually contain JSON text
  if (Buffer.isBuffer(pk)) {
    if (pk.length && pk[0] === 0x7b) { // '{'
      try {
        const parsed = JSON.parse(pk.toString('utf8'));
        if (parsed && Array.isArray(parsed.data)) {
          return Buffer.from(Uint8Array.from(parsed.data));
        }
        const maybeArr = Array.isArray(parsed) ? Uint8Array.from(parsed) : fromNumericKeyedObject(parsed);
        if (maybeArr) return Buffer.from(maybeArr);
      } catch { /* fall through */ }
    }
    return pk;
  }

  // 3) Postgres bytea hex as string (“\\xA1B2...”), which might be:
  //    a) real COSE bytes, or
  //    b) hex-encoded *JSON string* of bytes
  if (typeof pk === 'string') {
    if (pk.startsWith('\\x')) {
      const buf = Buffer.from(pk.slice(2), 'hex');
      // If hex-decoded buffer starts with '{', it's JSON — parse & reconstruct bytes
      if (buf.length && buf[0] === 0x7b) {
        try {
          const parsed = JSON.parse(buf.toString('utf8'));
          if (parsed && Array.isArray(parsed.data)) {
            return Buffer.from(Uint8Array.from(parsed.data));
          }
          const maybeArr = Array.isArray(parsed) ? Uint8Array.from(parsed) : fromNumericKeyedObject(parsed);
          if (maybeArr) return Buffer.from(maybeArr);
        } catch { /* not JSON */ }
      }
      return buf; // assume real COSE bytes
    }
    // Try base64url → base64 → utf8 fallback
    try { return Buffer.from(pk, 'base64url'); } catch {}
    try { return Buffer.from(pk, 'base64'); } catch {}
    return Buffer.from(pk, 'utf8');
  }

  // 4) Typed arrays / ArrayBuffer
  if (pk?.buffer && typeof pk.byteLength === 'number') {
    return Buffer.from(pk);
  }

  return Buffer.from(String(pk));
}

export async function startRegistration(user) {
  const { data: creds } = await supabase
    .from(CREDENTIALS_TABLE)
    .select('credential_id')
    .eq('user_id', user.id);

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID_HOST || RP_ID,
    userID: String(user.id),
    userName: user.phone || String(user.id),
    attestationType: 'none',
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      residentKey: 'required',
      userVerification: 'preferred',
    },
    excludeCredentials: (creds || []).map(c => ({
      id: c.credential_id,
      type: 'public-key',
    })),
    extensions: { credProps: true },
  });

  options.user.id = uuidToBase64Url(user.id);
  options.challenge = toB64Url(options.challenge);

  const { error: chErr } = await supabase
    .from('webauthn_challenge_store')
    .insert({ user_id: user.id, challenge: options.challenge, purpose: 'registration' });
  if (chErr) throw new Error(`Failed to save challenge (registration): ${chErr.message}`);

  return options;
}

export async function finishRegistration(user, credential) {
  console.log('finishRegistration origins111 =', origins);
  const { data: challengeRow } = await supabase
    .from('webauthn_challenge_store')
    .select('*')
    .eq('user_id', user.id)
    .eq('purpose', 'registration')
    .order('created_at', { ascending: false })
    .limit(1)
    .maybeSingle();

  if (!challengeRow?.challenge) {
    throw new Error('No saved registration challenge found; start registration again.');
  }

  console.log('finishRegistration origins =', origins);

  const verification = await verifyRegistrationResponse({
    response: credential,
    expectedChallenge: challengeRow.challenge,
    expectedOrigin: origins,
    expectedRPID: RP_ID_HOST || RP_ID,
    requireUserVerification: true,
  });

  if (!verification.verified) return { verified: false };

  const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;

  const pkBytes = credentialPublicKey instanceof Uint8Array
    ? credentialPublicKey
    : new Uint8Array(credentialPublicKey);

  const { error } = await supabase.from(CREDENTIALS_TABLE).insert({
    user_id: user.id,
    credential_id: Buffer.from(credentialID).toString('base64url'),
    public_key: pkBytes,
    counter,
    transports: credential?.transports || null,
  });
  if (error) throw error;

  return { verified: true };
}

export async function startAuthentication(user) {
  const options = await generateAuthenticationOptions({
    rpID: RP_ID_HOST || RP_ID,
    userVerification: 'preferred',
  });

  options.challenge = toB64Url(options.challenge);

  const { error: chErr } = await supabase
    .from('webauthn_challenge_store')
    .insert({ user_id: user.id, challenge: options.challenge, purpose: 'authentication' });
  if (chErr) throw new Error(`Failed to save challenge (authentication): ${chErr.message}`);

  return options;
}

export async function finishAuthentication(user, assertion) {
  const userId = user.id;
  const cred = user.cred;
console.log('A', userdId);
  try {
    const { data: challengeRow, error: chErr } = await supabase
      .from('webauthn_challenge_store')
      .select('*')
      .eq('user_id', userId)
      .eq('purpose', 'authentication')
      .order('created_at', { ascending: false })
      .limit(1)
      .maybeSingle();
console.log('B', userdId);
    if (chErr) return { verified: false, reason: `challenge fetch failed: ${chErr.message}` };
    if (!challengeRow?.challenge) return { verified: false, reason: 'no saved challenge' };
    if (!cred) return { verified: false, reason: 'no authenticator for credential id' };

    console.log('C', chErr);
    console.log('D', challengeRow);

    // 🔎 Decode clientDataJSON to see the origin & challenge the phone actually used
    let clientDataDecoded = null;
    try {
      clientDataDecoded = JSON.parse(
        Buffer.from(assertion.response.clientDataJSON, 'base64url').toString('utf8')
      );
      console.log('🔎 clientDataJSON.origin  =', clientDataDecoded.origin);
      console.log('🔎 clientDataJSON.type    =', clientDataDecoded.type);
      console.log('🔎 clientDataJSON.challenge(base64url)=', clientDataDecoded.challenge);
      console.log('🔎 expected.challenge      =', challengeRow.challenge);
    } catch (e) {
      console.warn('clientDataJSON parse failed:', e?.message || e);
    }

    // Also log what we expect
    console.log('🔎 expectedRPID   =', (process.env.RP_ID || '').replace(/^https?:\/\//,'').replace(/\/.*/,''));
    console.log('🔎 expectedOrigin =', process.env.RP_ORIGIN);

    const pk = normalizePublicKey(cred.public_key);
    try {
  // Heuristic: if the source was string "\\x..." and decoded started with '{' JSON,
  // normalizePublicKey would have returned bytes not equal to hex-decoded-utf8.
  // Simplify: if pk looks like COSE (starts with a CBOR map: a3/a4/a5), write back.
  const prefix = pk.slice(0, 1).toString('hex');
  if (['a3','a4','a5'].includes(prefix)) {
    await supabase
      .from(process.env.CREDENTIALS_TABLE || 'passkey_credentials')
      .update({ public_key: new Uint8Array(pk) })
      .eq('id', cred.id);
  }
} catch (e) {
  console.warn('⚠️ public_key auto-fix skipped:', e?.message || e);
}
    console.log('🔎 pk len =', pk.length, 'hex prefix =', pk.slice(0, 8).toString('hex'));

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response: assertion,
        expectedChallenge: challengeRow.challenge,
        expectedOrigin: process.env.RP_ORIGIN,
        expectedRPID: (process.env.RP_ID || '').replace(/^https?:\/\//,'').replace(/\/.*/,''),
        authenticator: {
          credentialID: Buffer.from(cred.credential_id, 'base64url'),
          credentialPublicKey: pk,
          counter: Number(cred.counter || 0),
          transports: cred.transports || [],
        },
      });
    } catch (err) {
      console.error('❌ verifyAuthenticationResponse threw:', err);
      // ⬇️ Return the *actual* message plus the decoded clientData to your client
      return {
        verified: false,
        reason: 'verification threw',
        error: String(err?.message || err),
        clientData: clientDataDecoded,
        expected: {
          origin: process.env.RP_ORIGIN,
          rpId: (process.env.RP_ID || '').replace(/^https?:\/\//,'').replace(/\/.*/,''),
          challenge: challengeRow.challenge,
        },
      };
    }

    console.log('🔍 Verification result:', JSON.stringify(verification, null, 2));
    if (!verification?.verified) {
      return {
        verified: false,
        reason: 'verification returned false',
        details: verification,
        clientData: clientDataDecoded,
      };
    }

    try {
      const { newCounter } = verification.authenticationInfo || {};
      if (typeof newCounter === 'number') {
        await supabase.from(process.env.CREDENTIALS_TABLE || 'passkey_credentials')
          .update({ counter: newCounter })
          .eq('id', cred.id);
      }
    } catch (e) {
      console.warn('⚠️ Counter update failed', e?.message || e);
    }

    return { verified: true };
  } catch (outer) {
    console.error('💥 finishAuthentication fatal error:', outer);
    return {
      verified: false,
      reason: 'outer exception',
      error: String(outer?.message || outer),
      stack: outer?.stack,
    };
  }
}

