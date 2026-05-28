# OAuth Server + Clients Example

Minimal OAuth 2.0 Authorization Code with PKCE flow: a Go server, a web client, and a VSCode extension.

## Architecture

```
┌──────────────────┐         ┌──────────────────┐         ┌──────────────────┐
│  VSCode Extension│         │     Browser       │         │   Go OAuth Server│
│  (localhost:3000)│         │                   │         │   (localhost:8080)│
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
         │                            │  4. Server redirects ◄──────│
         │                            │     to localhost:3000       │
         │                            │     with ?code=...&state=...│
         │                            │                             │
         │  5. Callback server ◄──────┤                             │
         │     captures auth code     │                             │
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

## Project Structure

```
oauth-server/          Go OAuth 2.0 authorization server
├── main.go            Server with /authorize, /token, /userinfo endpoints
└── go.mod

web-client/            Vanilla HTML/JS SPA (no dependencies)
└── index.html         Auth Code + PKCE flow in the browser

vscode-extension/      VSCode extension (TypeScript)
├── src/
│   ├── extension.ts       Commands: Sign In, Sign Out, Get User Info
│   └── authProvider.ts    AuthenticationProvider with PKCE flow
├── package.json
└── tsconfig.json
```

## Server Endpoints

| Method | Path         | Description                                  |
|--------|-------------|----------------------------------------------|
| GET    | `/authorize` | Shows login form, issues authorization code  |
| POST   | `/token`     | Exchanges auth code for access token (PKCE)  |
| GET    | `/userinfo`  | Returns user info (requires Bearer token)    |

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

### 3. Launch the VSCode extension

```bash
cd vscode-extension
npm install
npm run compile
code --extensionDevelopmentPath=$(pwd)
```

### 4. Authenticate (VSCode)

1. Open Command Palette (`Cmd+Shift+P`)
2. Run **OAuth Demo: Sign In**
3. Browser opens → log in with `demo` / `demo`
4. Redirects back → extension receives token
5. Run **OAuth Demo: Get User Info** to verify

## Demo Credentials

| Username | Password |
|----------|----------|
| `demo`   | `demo`   |
