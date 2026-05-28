package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

const listenAddr = ":8080"

type Client struct {
	ID           string
	RedirectURIs []string
	Scopes       []string
}

var registeredClients = map[string]*Client{
	"vscode-extension": {
		ID:           "vscode-extension",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		Scopes:       []string{"openid", "profile"},
	},
	"web-client": {
		ID:           "web-client",
		RedirectURIs: []string{"http://localhost:5500/"},
		Scopes:       []string{"openid", "profile", "email"},
	},
	"workspace": {
		ID:           "workspace",
		RedirectURIs: []string{"http://localhost:5501/"},
		Scopes:       []string{"openid", "profile"},
	},
}

type AuthCode struct {
	Code                string
	CodeChallenge       string
	CodeChallengeMethod string
	RedirectURI         string
	UserID              string
	Scopes              []string
	ExpiresAt           time.Time
}

type Token struct {
	AccessToken  string
	RefreshToken string
	UserID       string
	Scopes       []string
	ExpiresAt    time.Time
}

type RefreshToken struct {
	Token     string
	UserID    string
	ClientID  string
	Scopes    []string
	ExpiresAt time.Time
}

type Session struct {
	ID        string
	UserID    string
	ExpiresAt time.Time
}

type Store struct {
	mu            sync.RWMutex
	codes         map[string]*AuthCode
	tokens        map[string]*Token
	refreshTokens map[string]*RefreshToken
	sessions      map[string]*Session
}

func NewStore() *Store {
	return &Store{
		codes:         make(map[string]*AuthCode),
		tokens:        make(map[string]*Token),
		refreshTokens: make(map[string]*RefreshToken),
		sessions:      make(map[string]*Session),
	}
}

func (s *Store) SaveCode(ac *AuthCode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[ac.Code] = ac
}

func (s *Store) ConsumeCode(code string) *AuthCode {
	s.mu.Lock()
	defer s.mu.Unlock()
	ac, ok := s.codes[code]
	if !ok {
		return nil
	}
	delete(s.codes, code)
	return ac
}

func (s *Store) SaveToken(t *Token) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[t.AccessToken] = t
}

func (s *Store) GetToken(accessToken string) *Token {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tokens[accessToken]
}

func (s *Store) SaveRefreshToken(rt *RefreshToken) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshTokens[rt.Token] = rt
}

func (s *Store) ConsumeRefreshToken(token string) *RefreshToken {
	s.mu.Lock()
	defer s.mu.Unlock()
	rt, ok := s.refreshTokens[token]
	if !ok {
		return nil
	}
	delete(s.refreshTokens, token)
	return rt
}

func (s *Store) SaveSession(sess *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.ID] = sess
}

func (s *Store) GetSession(id string) *Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[id]
	if !ok || time.Now().After(sess.ExpiresAt) {
		return nil
	}
	return sess
}

var store = NewStore()

func randomString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func verifyPKCE(codeVerifier, codeChallenge, method string) bool {
	if method != "S256" {
		return false
	}
	h := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return computed == codeChallenge
}

func getClient(clientID string) *Client {
	return registeredClients[clientID]
}

func (c *Client) ValidateRedirectURI(uri string) bool {
	return slices.Contains(c.RedirectURIs, uri)
}

func (c *Client) ValidateScopes(requested []string) ([]string, bool) {
	if len(requested) == 0 {
		return c.Scopes, true
	}
	allowed := make(map[string]bool, len(c.Scopes))
	for _, s := range c.Scopes {
		allowed[s] = true
	}
	for _, s := range requested {
		if !allowed[s] {
			return nil, false
		}
	}
	return requested, true
}

func parseScopes(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Fields(s)
}

func joinScopes(scopes []string) string {
	return strings.Join(scopes, " ")
}

func getSessionUser(r *http.Request) string {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return ""
	}
	sess := store.GetSession(cookie.Value)
	if sess == nil {
		return ""
	}
	return sess.UserID
}

func setSessionCookie(w http.ResponseWriter, userID string) {
	sess := &Session{
		ID:        randomString(32),
		UserID:    userID,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	store.SaveSession(sess)
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sess.ID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400,
	})
}

func issueTokenPair(userID, clientID string, scopes []string) map[string]any {
	accessToken := randomString(32)
	refreshToken := randomString(32)

	store.SaveToken(&Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		UserID:       userID,
		Scopes:       scopes,
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	})

	store.SaveRefreshToken(&RefreshToken{
		Token:     refreshToken,
		UserID:    userID,
		ClientID:  clientID,
		Scopes:    scopes,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	})

	return map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": refreshToken,
		"scope":         joinScopes(scopes),
	}
}

func issueCodeAndRedirect(w http.ResponseWriter, r *http.Request, userID, redirectURI, state, codeChallenge, codeChallengeMethod string, scopes []string) {
	code := randomString(32)
	store.SaveCode(&AuthCode{
		Code:                code,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		RedirectURI:         redirectURI,
		UserID:              userID,
		Scopes:              scopes,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	})

	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}
	http.Redirect(w, r, fmt.Sprintf("%s%scode=%s&state=%s", redirectURI, sep, code, state), http.StatusFound)
}

var loginTmpl = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html><head><title>Login</title>
<style>
body { font-family: system-ui; max-width: 400px; margin: 80px auto; }
input, button { display: block; width: 100%; padding: 8px; margin: 8px 0; box-sizing: border-box; }
button { background: #0066cc; color: white; border: none; cursor: pointer; border-radius: 4px; }
</style></head>
<body>
<h2>Sign In</h2>
<form method="POST" action="/authorize">
  <input type="hidden" name="client_id" value="{{.ClientID}}">
  <input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
  <input type="hidden" name="state" value="{{.State}}">
  <input type="hidden" name="scope" value="{{.Scope}}">
  <input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
  <input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">
  <label>Username</label>
  <input type="text" name="username" required value="demo">
  <label>Password</label>
  <input type="password" name="password" required value="demo">
  <button type="submit">Sign In</button>
</form>
<p style="color:#888; font-size:12px;">Demo credentials: demo / demo</p>
</body></html>`))

var dashboardTmpl = template.Must(template.New("dashboard").Parse(`<!DOCTYPE html>
<html><head><title>Dashboard</title>
<style>
body { font-family: system-ui; max-width: 480px; margin: 80px auto; }
a { display: inline-block; padding: 10px 20px; background: #228833; color: white; text-decoration: none; border-radius: 6px; margin-top: 16px; }
</style></head>
<body>
<h2>Welcome, {{.UserID}}</h2>
<p>You are signed in.</p>
<a href="http://localhost:5501">Launch Workspace</a>
</body></html>`))

func handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		clientID := r.URL.Query().Get("client_id")
		redirectURI := r.URL.Query().Get("redirect_uri")
		state := r.URL.Query().Get("state")
		scope := r.URL.Query().Get("scope")
		codeChallenge := r.URL.Query().Get("code_challenge")
		codeChallengeMethod := r.URL.Query().Get("code_challenge_method")

		// No OAuth params — show dashboard if logged in
		if clientID == "" {
			if userID := getSessionUser(r); userID != "" {
				dashboardTmpl.Execute(w, map[string]string{"UserID": userID})
				return
			}
			loginTmpl.Execute(w, map[string]string{})
			return
		}

		responseType := r.URL.Query().Get("response_type")
		if responseType != "code" {
			jsonError(w, "unsupported_response_type", "Only response_type=code is supported", http.StatusBadRequest)
			return
		}

		client := getClient(clientID)
		if client == nil {
			jsonError(w, "invalid_client", "Unknown client_id", http.StatusBadRequest)
			return
		}

		if !client.ValidateRedirectURI(redirectURI) {
			jsonError(w, "invalid_request", "redirect_uri not registered for this client", http.StatusBadRequest)
			return
		}

		requestedScopes := parseScopes(scope)
		grantedScopes, ok := client.ValidateScopes(requestedScopes)
		if !ok {
			jsonError(w, "invalid_scope", "Requested scope exceeds client allowlist", http.StatusBadRequest)
			return
		}

		if codeChallengeMethod != "S256" {
			jsonError(w, "invalid_request", "code_challenge_method must be S256", http.StatusBadRequest)
			return
		}

		// SSO: if user has valid session, skip login and auto-issue code
		if userID := getSessionUser(r); userID != "" {
			issueCodeAndRedirect(w, r, userID, redirectURI, state, codeChallenge, codeChallengeMethod, grantedScopes)
			return
		}

		data := map[string]string{
			"ClientID":            clientID,
			"RedirectURI":         redirectURI,
			"State":               state,
			"Scope":               joinScopes(grantedScopes),
			"CodeChallenge":       codeChallenge,
			"CodeChallengeMethod": codeChallengeMethod,
		}
		loginTmpl.Execute(w, data)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	if username != "demo" || password != "demo" {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	setSessionCookie(w, username)

	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")

	if redirectURI == "" {
		dashboardTmpl.Execute(w, map[string]string{"UserID": username})
		return
	}

	scopes := parseScopes(r.FormValue("scope"))

	issueCodeAndRedirect(w, r, username, redirectURI, state,
		r.FormValue("code_challenge"), r.FormValue("code_challenge_method"), scopes)
}

func handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")
	clientID := r.FormValue("client_id")

	client := getClient(clientID)
	if client == nil {
		jsonError(w, "invalid_client", "Unknown client_id", http.StatusBadRequest)
		return
	}

	switch grantType {
	case "authorization_code":
		handleAuthCodeGrant(w, r, client)
	case "refresh_token":
		handleRefreshTokenGrant(w, r, client)
	default:
		jsonError(w, "unsupported_grant_type", "Supported: authorization_code, refresh_token", http.StatusBadRequest)
	}
}

func handleAuthCodeGrant(w http.ResponseWriter, r *http.Request, client *Client) {
	code := r.FormValue("code")
	ac := store.ConsumeCode(code)
	if ac == nil || time.Now().After(ac.ExpiresAt) {
		jsonError(w, "invalid_grant", "Invalid or expired code", http.StatusBadRequest)
		return
	}

	if ac.RedirectURI != r.FormValue("redirect_uri") {
		jsonError(w, "invalid_grant", "redirect_uri mismatch", http.StatusBadRequest)
		return
	}

	codeVerifier := r.FormValue("code_verifier")
	if !verifyPKCE(codeVerifier, ac.CodeChallenge, ac.CodeChallengeMethod) {
		jsonError(w, "invalid_grant", "PKCE verification failed", http.StatusBadRequest)
		return
	}

	tokenResp := issueTokenPair(ac.UserID, client.ID, ac.Scopes)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(tokenResp)
}

func handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, client *Client) {
	rtValue := r.FormValue("refresh_token")
	rt := store.ConsumeRefreshToken(rtValue)
	if rt == nil || time.Now().After(rt.ExpiresAt) {
		jsonError(w, "invalid_grant", "Invalid or expired refresh token", http.StatusBadRequest)
		return
	}

	if rt.ClientID != client.ID {
		jsonError(w, "invalid_grant", "Refresh token was not issued to this client", http.StatusBadRequest)
		return
	}

	// Rotation: old refresh token consumed, new pair issued
	tokenResp := issueTokenPair(rt.UserID, client.ID, rt.Scopes)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(tokenResp)
}

func handleUserInfo(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	token := store.GetToken(strings.TrimPrefix(auth, "Bearer "))
	if token == nil || time.Now().After(token.ExpiresAt) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	scopeSet := make(map[string]bool, len(token.Scopes))
	for _, s := range token.Scopes {
		scopeSet[s] = true
	}

	resp := map[string]string{"sub": token.UserID}
	if scopeSet["profile"] {
		resp["name"] = token.UserID
	}
	if scopeSet["email"] {
		resp["email"] = token.UserID + "@example.com"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	baseURL := fmt.Sprintf("http://localhost%s", listenAddr)

	discovery := map[string]any{
		"issuer":                 baseURL,
		"authorization_endpoint": baseURL + "/authorize",
		"token_endpoint":         baseURL + "/token",
		"userinfo_endpoint":      baseURL + "/userinfo",
		"end_session_endpoint":   baseURL + "/logout",
		"response_types_supported":             []string{"code"},
		"grant_types_supported":                []string{"authorization_code", "refresh_token"},
		"scopes_supported":                     []string{"openid", "profile", "email"},
		"code_challenge_methods_supported":     []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"subject_types_supported":              []string{"public"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(discovery)
}

func jsonError(w http.ResponseWriter, errCode, desc string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": desc,
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	redirectTo := r.URL.Query().Get("redirect_uri")
	if redirectTo == "" {
		redirectTo = "/authorize"
	}
	http.Redirect(w, r, redirectTo, http.StatusFound)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", handleAuthorize)
	mux.HandleFunc("/token", handleToken)
	mux.HandleFunc("/userinfo", handleUserInfo)
	mux.HandleFunc("/logout", handleLogout)
	mux.HandleFunc("/.well-known/openid-configuration", handleDiscovery)

	fmt.Printf("OAuth server running on http://localhost%s\n", listenAddr)
	fmt.Println("Endpoints:")
	fmt.Println("  GET  /authorize                       — authorization + SSO")
	fmt.Println("  POST /token                           — token (auth_code + refresh_token)")
	fmt.Println("  GET  /userinfo                        — protected resource (scope-filtered)")
	fmt.Println("  GET  /logout                          — clear session + redirect")
	fmt.Println("  GET  /.well-known/openid-configuration — discovery document")
	log.Fatal(http.ListenAndServe(listenAddr, corsMiddleware(mux)))
}
