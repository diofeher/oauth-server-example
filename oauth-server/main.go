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
	"strings"
	"sync"
	"time"
)

const listenAddr = ":8080"

var validClients = map[string]bool{
	"vscode-extension": true,
	"web-client":       true,
}

type AuthCode struct {
	Code                string
	CodeChallenge       string
	CodeChallengeMethod string
	RedirectURI         string
	UserID              string
	ExpiresAt           time.Time
}

type Token struct {
	AccessToken string
	UserID      string
	ExpiresAt   time.Time
}

type Store struct {
	mu     sync.RWMutex
	codes  map[string]*AuthCode
	tokens map[string]*Token
}

func NewStore() *Store {
	return &Store{
		codes:  make(map[string]*AuthCode),
		tokens: make(map[string]*Token),
	}
}

func (s *Store) SaveCode(ac *AuthCode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[ac.Code] = ac
}

func (s *Store) GetCode(code string) *AuthCode {
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

func handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		data := map[string]string{
			"ClientID":            r.URL.Query().Get("client_id"),
			"RedirectURI":        r.URL.Query().Get("redirect_uri"),
			"State":              r.URL.Query().Get("state"),
			"CodeChallenge":      r.URL.Query().Get("code_challenge"),
			"CodeChallengeMethod": r.URL.Query().Get("code_challenge_method"),
		}
		loginTmpl.Execute(w, data)
		return
	}

	r.ParseForm()

	username := r.FormValue("username")
	password := r.FormValue("password")
	if username != "demo" || password != "demo" {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")

	code := randomString(32)
	store.SaveCode(&AuthCode{
		Code:                code,
		CodeChallenge:       r.FormValue("code_challenge"),
		CodeChallengeMethod: r.FormValue("code_challenge_method"),
		RedirectURI:         redirectURI,
		UserID:              username,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	})

	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}
	http.Redirect(w, r, fmt.Sprintf("%s%scode=%s&state=%s", redirectURI, sep, code, state), http.StatusFound)
}

func handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	r.ParseForm()

	grantType := r.FormValue("grant_type")
	if grantType != "authorization_code" {
		jsonError(w, "unsupported_grant_type", "Only authorization_code supported", http.StatusBadRequest)
		return
	}

	cid := r.FormValue("client_id")
	if !validClients[cid] {
		jsonError(w, "invalid_client", "Unknown client_id", http.StatusBadRequest)
		return
	}

	code := r.FormValue("code")
	ac := store.GetCode(code)
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

	accessToken := randomString(32)
	store.SaveToken(&Token{
		AccessToken: accessToken,
		UserID:      ac.UserID,
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
	})
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"sub":  token.UserID,
		"name": token.UserID,
	})
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

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", handleAuthorize)
	mux.HandleFunc("/token", handleToken)
	mux.HandleFunc("/userinfo", handleUserInfo)

	fmt.Printf("OAuth server running on http://localhost%s\n", listenAddr)
	fmt.Println("Endpoints:")
	fmt.Println("  GET  /authorize  — authorization endpoint (shows login)")
	fmt.Println("  POST /token      — token endpoint")
	fmt.Println("  GET  /userinfo   — protected resource")
	log.Fatal(http.ListenAndServe(listenAddr, corsMiddleware(mux)))
}
