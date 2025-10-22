# Auth Server (OTP + Passkeys) — fixed
- Platform, discoverable passkeys
- Omit allowCredentials on login
- Robust login/finish (404 if cred not found; passes authenticator)
- CREDENTIALS_TABLE=passkey_credentials

## Setup
1) `cp .env.example .env` and fill values (JWT_SECRET, SUPABASE_*, RP_ID/ORIGIN).
2) Run `schema.sql` in Supabase SQL editor.
3) `npm i && npm run dev`

## Endpoints
- POST /auth/request-otp { phone }
- POST /auth/verify-otp { phone, token } -> { token }
- POST /passkey/register/start (Bearer appJWT)
- POST /passkey/register/finish (Bearer appJWT) { credential }
- POST /passkey/login/start { phone } -> { options, userId }
- POST /passkey/login/finish { userId, assertion } -> { token }
# passkey-demo
# passkey-demo
