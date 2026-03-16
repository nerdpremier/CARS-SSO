# CARS-SSO (Vercel + Node) — Overview

This repo is a **static HTML/CSS/vanilla JS** frontend served by Vercel, backed by **Node serverless functions** under `api/` with shared utilities in `lib/`.

## Runtime model (how requests are routed)

Vercel routing is defined in `vercel.json`.

### Pages (static)

| URL | File |
|---|---|
| `/` / `/login` | `login.html` |
| `/register` | `register.html` |
| `/mfa` | `mfa-verify.html` |
| `/welcome` | `welcome.html` |
| `/forgot-password` | `forgot-password.html` |
| `/reset-password` | `reset-password.html` |
| `/oauth/authorize` | `authorize.html` |
| `/developer` | `developer-portal.html` |

Static assets are also served from repo root (e.g. `style.css`, `script.js`, `effects.js`, `developer-portal.css`).

### API endpoints (serverless)

| URL | Entry file | Notes |
|---|---|---|
| `/api/csrf` | `api/csrf.js` | Issues CSRF token cookie (double-submit) |
| `/api/assess` | `api/assess.js` | Risk assessment before password check |
| `/api/auth` | `api/auth.js` | Register/login + email verification + verification polling |
| `/api/mfa` | `api/mfa.js` | Combined: verify/resend (dispatches to `lib/verify-mfa.js`, `lib/resend-mfa.js`) |
| `/api/password` | `api/password.js` | Combined: forgot/reset (dispatches to `lib/forgot-password.js`, `lib/reset-password.js`) |
| `/api/session` | `api/session.js` | Verifies current session cookie |
| `/api/session-risk` | `api/session-risk.js` | (Used for risk/session info; see file) |
| `/api/logout` | `api/logout.js` | POST logout; GET supports `logout-redirect` + cron cleanup |
| `/api/oauth/*` | `api/oauth.js` | Combined OAuth router (see below) |

#### OAuth sub-routes (all served by `api/oauth.js`)

| URL | Purpose |
|---|---|
| `/api/oauth/clients` | Developer portal CRUD for OAuth clients (cookie-auth) |
| `/api/oauth/authorize` | Consent verification + authorization code issuance (PKCE supported) |
| `/api/oauth/token` | Token exchange (authorization_code / refresh_token rotation) |
| `/api/oauth/userinfo` | Bearer access token → scoped user info |
| `/api/oauth/revoke` | RFC 7009 revoke |
| `/api/oauth/sso-exchange` | One-time SSO token exchange (redirect-back flow) |

## Key user flows (high level)

### Login (LOW/MEDIUM/HIGH)

```mermaid
flowchart TD
  LoginPage[login.html] -->|POST| Csrf[GET /api/csrf]
  LoginPage -->|POST| Assess[POST /api/assess]
  Assess -->|returns logId+risk| LoginPage
  LoginPage -->|POST action=login| Auth[POST /api/auth]
  Auth -->|LOW: Set-Cookie session_token| Welcome[/welcome]
  Auth -->|MEDIUM: MFA required| MfaPage[/mfa]
  Auth -->|HIGH: reject| LoginPage
  MfaPage -->|POST action=verify| MfaApi[POST /api/mfa]
  MfaApi -->|Set-Cookie session_token| Welcome
```

### OAuth authorization code (consent + PKCE)

```mermaid
flowchart TD
  ClientApp[ThirdPartyApp] -->|redirect to| ConsentPage[/oauth/authorize]
  ConsentPage -->|GET| OauthAuthorizeGet[GET /api/oauth/authorize]
  OauthAuthorizeGet -->|401 if not signed in| Login[/login?next=...]
  ConsentPage -->|POST allow/deny + CSRF| OauthAuthorizePost[POST /api/oauth/authorize]
  OauthAuthorizePost -->|redirect_url with code| ClientApp
  ClientApp -->|POST grant=authorization_code + code_verifier| Token[POST /api/oauth/token]
  Token -->|access_token| ClientApp
  ClientApp -->|GET Bearer| UserInfo[GET /api/oauth/userinfo]
```

## Code map

- **Frontend**
  - `style.css`: shared styling + components/tokens.
  - `effects.js`: background / transitions / visual effects.
  - `script.js`: core auth UI logic (login/register/mfa/password reset/session check).
  - `authorize.js`: consent page logic (PKCE + CSRF) for `/oauth/authorize`.
  - `developer-portal.js` + `developer-portal.css`: OAuth client management UI.
- **Backend**
  - `api/*.js`: Vercel serverless entrypoints.
  - `lib/*.js`: shared helpers (DB, mail, CSRF, risk scoring, rate limit, etc.).

## Local development

This repo includes a tiny dev server (`server.js`) that emulates the `vercel.json` rewrites:
- Serves the static pages (e.g. `/login` → `login.html`)
- Dispatches `/api/*` requests to the existing serverless handlers in `api/`

### Run

1. Configure environment variables (same as production). At minimum, the startup check requires:
   - `JWT_SECRET`, `CSRF_SECRET`, `MFA_PEPPER`, `OAUTH_SECRET_PEPPER`, `CRON_SECRET`
   - `EMAIL_USER`, `EMAIL_PASS`, `BASE_URL`, `DATABASE_URL`
2. Start:

```bash
npm install
npm start
```

Then open `http://127.0.0.1:3000`.

