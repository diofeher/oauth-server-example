import * as vscode from "vscode";
import * as crypto from "crypto";
import * as http from "http";

const AUTHORIZE_URL = "http://localhost:8080/authorize";
const TOKEN_URL = "http://localhost:8080/token";
const CLIENT_ID = "vscode-extension";
const CALLBACK_PORT = 3000;
const REDIRECT_URI = `http://localhost:${CALLBACK_PORT}/callback`;

const SESSION_KEY = "oauthDemo.session";

export class OAuthAuthenticationProvider
  implements vscode.AuthenticationProvider
{
  static readonly id = "oauthDemo";

  private _sessionChangeEmitter =
    new vscode.EventEmitter<vscode.AuthenticationProviderAuthenticationSessionsChangeEvent>();
  readonly onDidChangeSessions = this._sessionChangeEmitter.event;

  private _currentSession: vscode.AuthenticationSession | undefined;

  constructor(private readonly context: vscode.ExtensionContext) {}

  async getSessions(): Promise<vscode.AuthenticationSession[]> {
    const stored = await this.context.secrets.get(SESSION_KEY);
    if (stored) {
      this._currentSession = JSON.parse(stored);
      return [this._currentSession!];
    }
    return [];
  }

  async createSession(
    _scopes: string[]
  ): Promise<vscode.AuthenticationSession> {
    const { codeVerifier, codeChallenge } = generatePKCE();
    const state = crypto.randomBytes(16).toString("hex");

    const authCode = await this.promptAuthorization(codeChallenge, state);

    const tokenData = await exchangeCodeForToken(authCode, codeVerifier);

    const session: vscode.AuthenticationSession = {
      id: crypto.randomUUID(),
      accessToken: tokenData.access_token,
      account: { id: "demo", label: "demo" },
      scopes: [],
    };

    this._currentSession = session;
    await this.context.secrets.store(SESSION_KEY, JSON.stringify(session));

    this._sessionChangeEmitter.fire({
      added: [session],
      removed: [],
      changed: [],
    });

    return session;
  }

  async removeSession(): Promise<void> {
    const removed = this._currentSession;
    this._currentSession = undefined;
    await this.context.secrets.delete(SESSION_KEY);

    if (removed) {
      this._sessionChangeEmitter.fire({
        added: [],
        removed: [removed],
        changed: [],
      });
    }
  }

  private promptAuthorization(
    codeChallenge: string,
    state: string
  ): Promise<string> {
    return new Promise((resolve, reject) => {
      const server = http.createServer((req, res) => {
        const url = new URL(req.url!, `http://localhost:${CALLBACK_PORT}`);
        if (url.pathname !== "/callback") {
          res.writeHead(404);
          res.end();
          return;
        }

        const returnedState = url.searchParams.get("state");
        if (returnedState !== state) {
          res.writeHead(400);
          res.end("State mismatch");
          reject(new Error("State mismatch"));
          server.close();
          return;
        }

        const code = url.searchParams.get("code");
        if (!code) {
          res.writeHead(400);
          res.end("Missing code");
          reject(new Error("Missing authorization code"));
          server.close();
          return;
        }

        res.writeHead(200, { "Content-Type": "text/html" });
        res.end(
          "<html><body><h2>Authorization successful!</h2><p>You can close this tab and return to VS Code.</p></body></html>"
        );
        server.close();
        resolve(code);
      });

      server.listen(CALLBACK_PORT, () => {
        const params = new URLSearchParams({
          client_id: CLIENT_ID,
          redirect_uri: REDIRECT_URI,
          response_type: "code",
          state,
          code_challenge: codeChallenge,
          code_challenge_method: "S256",
        });

        vscode.env.openExternal(
          vscode.Uri.parse(`${AUTHORIZE_URL}?${params.toString()}`)
        );
      });

      setTimeout(() => {
        server.close();
        reject(new Error("Authorization timed out"));
      }, 120_000);
    });
  }
}

function generatePKCE(): { codeVerifier: string; codeChallenge: string } {
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  const codeChallenge = crypto
    .createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");
  return { codeVerifier, codeChallenge };
}

async function exchangeCodeForToken(
  code: string,
  codeVerifier: string
): Promise<{ access_token: string; token_type: string; expires_in: number }> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: CLIENT_ID,
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: codeVerifier,
  });

  const resp = await fetch(TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });

  if (!resp.ok) {
    const err = await resp.text();
    throw new Error(`Token exchange failed: ${err}`);
  }

  return resp.json() as Promise<{
    access_token: string;
    token_type: string;
    expires_in: number;
  }>;
}
