# OAuth Server + Clients Example

Minimal OAuth 2.0 Authorization Code with PKCE flow: a Go server, a web client, a workspace app (SSO), and a VSCode extension.

## Architecture

### Direct Login Flow (web-client, VSCode extension)

```
┌──────────────────┐         ┌──────────────────┐         ┌──────────────────┐
│      Client      │         │     Browser       │         │   Go OAuth Server│
│                  │         │                   │         │   (localhost:8080)│
└────────┬─────────┘         └────────┬──────────┘         └────────┬─────────┘
         │                            │                             │
         │  1. Generate PKCE pair     │                             │
         │     (code_verifier +       │                             │
         │      code_challenge)       │                             │
         │                            │                             │
         │  2. Open browser ──────────┼──► GET /authorize           │
         │     with code_challenge    │     ?client_id=...          │
         │     + state                │     &code_challenge=...     │
         │                            │     &state=...              │
         │                            │                             │
         │                            │  3. User logs in ──────────►│
         │                            │     (demo / demo)           │
         │                            │                             │
         │                            │  4. Server sets session ◄───│
         │                            │     cookie + redirects      │
         │                            │     with ?code=...&state=...│
         │                            │                             │
         │  5. Client captures  ◄─────┤                             │
         │     auth code              │                             │
         │                            │                             │
         │  6. POST /token ─────────────────────────────────────────►
         │     with code + code_verifier                            │
         │                                                          │
         │  7. Server verifies PKCE ◄───────────────────────────────│
         │     returns access_token                                 │
         │                                                          │
         │  8. GET /userinfo ───────────────────────────────────────►
         │     Authorization: Bearer <token>                        │
         │                                                          │
         │  9. Returns user data ◄──────────────────────────────────│
         └──────────────────────────────────────────────────────────┘
```

### SSO Flow (workspace, launched from oauth-server dashboard)

```
┌──────────────────┐         ┌──────────────────┐         ┌──────────────────┐
│    Workspace     │         │     Browser       │         │   Go OAuth Server│
│ (localhost:5501) │         │  (has session     │         │   (localhost:8080)│
│                  │         │   cookie from     │         │                  │
│                  │         │   prior login)    │         │                  │
└────────┬─────────┘         └────────┬──────────┘         └────────┬─────────┘
         │                            │                             │
         │  1. No token in            │                             │
         │     sessionStorage         │                             │
         │                            │                             │
         │  2. Generate PKCE pair     │                             │
         │     redirect to ───────────┼──► GET /authorize           │
         │     /authorize             │     + session cookie        │
         │                            │                             │
         │                            │  3. Server finds valid ─────│
         │                            │     session cookie          │
         │                            │     SKIPS login form        │
         │                            │                             │
         │                            │  4. Auto-issues code ◄──────│
         │                            │     redirects back          │
         │                            │     with ?code=...&state=...│
         │                            │                             │
         │  5. Exchange code ──────────────────────────────────────►│
         │     for token (PKCE)       │                             │
         │                            │                             │
         │  6. Authenticated ◄──────────────────────────────────────│
         │     (no user interaction)  │                             │
         └──────────────────────────────────────────────────────────┘
```

### Logout Flow

```
Client ──► GET /logout?redirect_uri=... ──► OAuth Server
                                               │
                                     Expires session cookie
                                               │
                                     302 redirect to redirect_uri
                                               │
Client (login form) ◄─────────────────────────┘
```

## Project Structure

```
oauth-server/          Go OAuth 2.0 authorization server
├── main.go            All endpoints: /authorize, /token, /userinfo, /logout
└── go.mod

web-client/            Vanilla HTML/JS SPA (no dependencies)
└── index.html         Auth Code + PKCE flow in the browser

workspace/             Vanilla HTML/JS SPA (no dependencies)
└── index.html         Auto-authenticates via SSO (silent redirect)

vscode-extension/      VSCode extension (TypeScript)
├── src/
│   ├── extension.ts       Commands: Sign In, Sign Out, Get User Info
│   └── authProvider.ts    AuthenticationProvider with PKCE flow
├── package.json
└── tsconfig.json
```

## Server Endpoints

| Method | Path         | Description                                          |
|--------|-------------|------------------------------------------------------|
| GET    | `/authorize` | Login form, or silent redirect if session cookie set |
| POST   | `/authorize` | Validates credentials, sets session cookie           |
| POST   | `/token`     | Exchanges auth code for access token (PKCE)          |
| GET    | `/userinfo`  | Returns user info (requires Bearer token)            |
| GET    | `/logout`    | Clears session cookie, redirects to `redirect_uri`   |

## Quick Start

### 1. Start the OAuth server

```bash
cd oauth-server
go run .
```

Server runs on `http://localhost:8080`.

### 2. Open the web client

```bash
cd web-client
python3 -m http.server 5500
```

Open `http://localhost:5500` → click **Sign In** → log in with `demo` / `demo` → redirected back with token.

### 3. Try SSO with workspace

```bash
cd workspace
python3 -m http.server 5501
```

Go to `http://localhost:8080/authorize` → log in → click **Launch Workspace** → workspace opens and is automatically authenticated (no second login).

### 4. Launch the VSCode extension

```bash
cd vscode-extension
npm install
npm run compile
code --extensionDevelopmentPath=$(pwd)
```

1. Open Command Palette (`Cmd+Shift+P`)
2. Run **OAuth Demo: Sign In**
3. Browser opens → log in with `demo` / `demo`
4. Redirects back → extension receives token
5. Run **OAuth Demo: Get User Info** to verify

## Demo Credentials

| Username | Password |
|----------|----------|
| `demo`   | `demo`   |

## Architecture Trade-offs and Limitations

### In-memory storage

All auth codes, tokens, and sessions are stored in a Go `map` behind a `sync.RWMutex`. This means:

- **All state lost on server restart** — tokens and sessions disappear
- **No horizontal scaling** — can't run multiple server instances behind a load balancer
- **No token revocation propagation** — a real system would use Redis, a database, or signed JWTs

### Session cookie security

- **SameSite=Lax** — protects against CSRF on POST but allows the cookie to be sent on top-level GET redirects (required for SSO flow to work)
- **No Secure flag** — set because we're on `http://localhost`. Production must use `Secure; SameSite=Strict` over HTTPS
- **HttpOnly** — prevents JavaScript access to session cookie (good), but means the client can't inspect session state

### Token storage on clients (web-client, workspace)

- Tokens stored in **`sessionStorage`** — not accessible to other tabs, lost on tab close
- **Not in `localStorage`** — avoids persistence across sessions, but means each tab needs its own auth flow
- **Not in HttpOnly cookies** — would be more secure against XSS, but requires a backend-for-frontend (BFF) pattern which adds complexity
- **Vulnerable to XSS** — any injected script in the page can read `sessionStorage` and steal the token. Real apps should use a BFF or `HttpOnly` cookie approach

### PKCE without client secrets

- All clients are **public clients** (no client secret) — correct for SPAs and native apps per OAuth 2.1
- PKCE prevents authorization code interception, but **does not authenticate the client itself**
- A malicious app that knows the `client_id` could initiate flows — real systems should validate `redirect_uri` against a registered allowlist

### SSO silent redirect

- Works because the browser sends the session cookie to the OAuth server during the redirect
- **User sees a brief flash** — browser navigates to OAuth server and back. Could use a hidden iframe for a smoother experience, but that adds complexity and has cross-origin restrictions
- **Session fixation risk** — if an attacker can set the session cookie before the user logs in. Mitigated here by generating a new session ID on each login
- **No consent screen** — the server auto-issues codes for any registered client when a session exists. A real IdP should prompt for user consent per-client on first use

### Hardcoded URLs and ports

- All client apps have `localhost:8080` hardcoded for the OAuth server
- Workspace URL (`localhost:5501`) is hardcoded in the server's dashboard template
- Production would use environment variables or a discovery endpoint (`.well-known/openid-configuration`)

### No refresh tokens

- Access tokens expire in 1 hour with no way to renew without re-authenticating
- A real system would issue refresh tokens and support the `refresh_token` grant type
- For the SSO case this is less of a problem since the session cookie can silently re-issue tokens

### No HTTPS

- All communication is unencrypted `http://localhost`
- Tokens and credentials are visible in transit — fine for local development, unacceptable in production
- `crypto.subtle` (used for PKCE SHA-256 in the browser) requires a secure context — works on `localhost` but would fail on plain HTTP in production
