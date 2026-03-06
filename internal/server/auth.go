package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	accessCookieName = "scudozi_access"
	csrfCookieName   = "scudozi_csrf"
	accessMaxAgeSec  = 12 * 60 * 60
)

var (
	srpNHex = strings.Join([]string{
		"AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050",
		"A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50",
		"E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8",
		"55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B",
		"CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748",
		"544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6",
		"AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6",
		"94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73",
	}, "")
)

type srpSession struct {
	Username   string
	Purpose    string
	A          *big.Int
	B          *big.Int
	expectedM1 []byte
	M2         []byte
	ExpiresAt  time.Time
}

type accessSession struct {
	Username  string
	Role      string
	CSRF      string
	ExpiresAt time.Time
}

type stepupToken struct {
	Username  string
	Role      string
	ExpiresAt time.Time
}

type authStateStore struct {
	mu     sync.Mutex
	srp    map[string]srpSession
	access map[string]accessSession
	stepup map[string]stepupToken
}

var (
	authState = authStateStore{
		srp:    map[string]srpSession{},
		access: map[string]accessSession{},
		stepup: map[string]stepupToken{},
	}
	srpN        *big.Int
	srpG        *big.Int
	srpK        *big.Int
	srpSalt     []byte
	srpVerifier *big.Int
	nBytes      int

	generatedUsername string
	generatedPassword string
)

type contextKey string

const sessionContextKey = contextKey("session")

func initAuth() error {
	var ok bool
	srpN, ok = new(big.Int).SetString(srpNHex, 16)
	if !ok {
		return errors.New("failed to parse SRP modulus")
	}
	srpG = big.NewInt(2)
	nBytes = (srpN.BitLen() + 7) / 8

	if strings.TrimSpace(os.Getenv("SCUDOZI_DEMO_USER")) != "" && strings.TrimSpace(os.Getenv("SCUDOZI_DEMO_PASS")) != "" {
		generatedUsername = strings.TrimSpace(os.Getenv("SCUDOZI_DEMO_USER"))
		generatedPassword = strings.TrimSpace(os.Getenv("SCUDOZI_DEMO_PASS"))
	} else {
		generatedUsername = "admin-" + mustRandToken(4)
		generatedPassword = mustRandToken(12)
	}
	srpSalt = mustRandBytes(16)

	srpK = bigFromBytes(hashBytes(padToN(srpN), padToN(srpG)))
	x := computeX(generatedUsername, generatedPassword, srpSalt)
	srpVerifier = new(big.Int).Exp(srpG, x, srpN)

	logAudit("auth.credentials.generated", generatedUsername, "admin", "success", map[string]any{
		"note": "Generated startup credentials for SRP login",
	})
	fmt.Printf("[Scudozi] SRP Username: %s\n", generatedUsername)
	fmt.Printf("[Scudozi] SRP Password: %s\n", generatedPassword)
	fmt.Printf("[Scudozi] Keep these credentials secure; restart regenerates them.\n")
	writeDemoCredsFile(generatedUsername, generatedPassword)
	return nil
}

type srpStartRequest struct {
	Username string `json:"username"`
	A        string `json:"a"`
	Purpose  string `json:"purpose"`
}

type srpStartResponse struct {
	SessionID string `json:"session_id"`
	Salt      string `json:"salt"`
	B         string `json:"b"`
}

func handleSRPStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cleanupAuthState()

	var req srpStartRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	purpose := strings.ToLower(strings.TrimSpace(req.Purpose))
	if purpose == "" {
		purpose = "login"
	}
	if purpose != "login" && purpose != "stepup" {
		http.Error(w, "invalid purpose", http.StatusBadRequest)
		return
	}

	if req.Username != generatedUsername {
		logAudit("auth.srp.start", req.Username, "unknown", "denied", map[string]any{"reason": "username_mismatch"})
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	if purpose == "stepup" {
		sess, ok := sessionFromRequest(r)
		if !ok || sess.Username != req.Username {
			logAudit("auth.srp.start.stepup", req.Username, "admin", "denied", map[string]any{"reason": "not_authenticated"})
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
	}

	A, ok := new(big.Int).SetString(req.A, 16)
	if !ok || A.Sign() <= 0 || new(big.Int).Mod(A, srpN).Sign() == 0 {
		http.Error(w, "invalid SRP public value", http.StatusBadRequest)
		return
	}

	b, err := randInt(32)
	if err != nil {
		http.Error(w, "failed to create session", http.StatusInternalServerError)
		return
	}
	gb := new(big.Int).Exp(srpG, b, srpN)
	kv := new(big.Int).Mul(srpK, srpVerifier)
	B := new(big.Int).Add(kv, gb)
	B.Mod(B, srpN)

	u := bigFromBytes(hashBytes(padToN(A), padToN(B)))
	vu := new(big.Int).Exp(srpVerifier, u, srpN)
	aux := new(big.Int).Mul(A, vu)
	aux.Mod(aux, srpN)
	S := new(big.Int).Exp(aux, b, srpN)
	K := hashBytes(padToN(S))

	m1 := computeM1(req.Username, srpSalt, A, B, K)
	m2 := computeM2(A, m1, K)

	sid, err := randToken(18)
	if err != nil {
		http.Error(w, "failed to create session", http.StatusInternalServerError)
		return
	}

	authState.mu.Lock()
	authState.srp[sid] = srpSession{
		Username:   req.Username,
		Purpose:    purpose,
		A:          A,
		B:          B,
		expectedM1: m1,
		M2:         m2,
		ExpiresAt:  time.Now().Add(2 * time.Minute),
	}
	authState.mu.Unlock()

	logAudit("auth.srp.start", req.Username, "admin", "success", map[string]any{"purpose": purpose})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(srpStartResponse{SessionID: sid, Salt: hex.EncodeToString(srpSalt), B: strings.ToLower(B.Text(16))})
}

type srpVerifyRequest struct {
	SessionID string `json:"session_id"`
	A         string `json:"a"`
	M1        string `json:"m1"`
}

type srpVerifyResponse struct {
	M2          string `json:"m2"`
	Role        string `json:"role,omitempty"`
	Username    string `json:"username,omitempty"`
	ExpiresIn   int    `json:"expires_in"`
	StepupToken string `json:"stepup_token,omitempty"`
}

func handleSRPVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cleanupAuthState()

	var req srpVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	presentedA, ok := new(big.Int).SetString(req.A, 16)
	if !ok {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	m1Bytes, err := hex.DecodeString(req.M1)
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	authState.mu.Lock()
	session, ok := authState.srp[req.SessionID]
	if ok {
		delete(authState.srp, req.SessionID)
	}
	authState.mu.Unlock()
	if !ok || time.Now().After(session.ExpiresAt) {
		http.Error(w, "session expired", http.StatusUnauthorized)
		return
	}

	if session.A.Cmp(presentedA) != 0 || !hmac.Equal(session.expectedM1, m1Bytes) {
		logAudit("auth.srp.verify", session.Username, "admin", "denied", map[string]any{"reason": "proof_mismatch", "purpose": session.Purpose})
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if session.Purpose == "login" {
		accessToken, _ := randToken(24)
		csrfToken, _ := randToken(20)
		expires := time.Now().Add(accessMaxAgeSec * time.Second)

		authState.mu.Lock()
		authState.access[accessToken] = accessSession{Username: session.Username, Role: "admin", CSRF: csrfToken, ExpiresAt: expires}
		authState.mu.Unlock()

		secure := isSecureRequest(r)
		setAccessCookie(w, accessToken, secure)
		setCSRFCookie(w, csrfToken, secure)
		logAudit("auth.login", session.Username, "admin", "success", nil)

		_ = json.NewEncoder(w).Encode(srpVerifyResponse{
			M2:        hex.EncodeToString(session.M2),
			Role:      "admin",
			Username:  session.Username,
			ExpiresIn: accessMaxAgeSec,
		})
		return
	}

	if sess, ok := sessionFromRequest(r); !ok || sess.Username != session.Username || sess.Role != "admin" {
		logAudit("auth.stepup", session.Username, "admin", "denied", map[string]any{"reason": "no_active_session"})
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}

	stepToken, _ := randToken(18)
	authState.mu.Lock()
	authState.stepup[stepToken] = stepupToken{Username: session.Username, Role: "admin", ExpiresAt: time.Now().Add(2 * time.Minute)}
	authState.mu.Unlock()
	logAudit("auth.stepup", session.Username, "admin", "success", nil)

	_ = json.NewEncoder(w).Encode(srpVerifyResponse{
		M2:          hex.EncodeToString(session.M2),
		StepupToken: stepToken,
		ExpiresIn:   120,
	})
}

func handleSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sess, ok := sessionFromRequest(r)
	w.Header().Set("Content-Type", "application/json")
	if !ok {
		_ = json.NewEncoder(w).Encode(map[string]any{"authenticated": false})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"authenticated": true,
		"username":      sess.Username,
		"role":          sess.Role,
	})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sess, ok := sessionFromRequest(r)
	if ok {
		logAudit("auth.logout", sess.Username, sess.Role, "success", nil)
	}
	clearSessionCookies(w, isSecureRequest(r))
	w.WriteHeader(http.StatusNoContent)
}

func sessionFromRequest(r *http.Request) (accessSession, bool) {
	c, err := r.Cookie(accessCookieName)
	if err != nil || c.Value == "" {
		return accessSession{}, false
	}
	authState.mu.Lock()
	defer authState.mu.Unlock()
	sess, ok := authState.access[c.Value]
	if !ok || time.Now().After(sess.ExpiresAt) {
		if ok {
			delete(authState.access, c.Value)
		}
		return accessSession{}, false
	}
	return sess, true
}

func validateStepupToken(username, role, token string) bool {
	cleanupAuthState()
	authState.mu.Lock()
	defer authState.mu.Unlock()
	entry, ok := authState.stepup[token]
	if !ok {
		return false
	}
	delete(authState.stepup, token)
	if time.Now().After(entry.ExpiresAt) {
		return false
	}
	return entry.Username == username && entry.Role == role
}

func validateCSRF(r *http.Request, sess accessSession) bool {
	head := strings.TrimSpace(r.Header.Get("X-CSRF-Token"))
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		return false
	}
	return head != "" && head == cookie.Value && head == sess.CSRF
}

func cleanupAuthState() {
	now := time.Now()
	authState.mu.Lock()
	defer authState.mu.Unlock()
	for id, s := range authState.srp {
		if now.After(s.ExpiresAt) {
			delete(authState.srp, id)
		}
	}
	for token, s := range authState.access {
		if now.After(s.ExpiresAt) {
			delete(authState.access, token)
		}
	}
	for token, s := range authState.stepup {
		if now.After(s.ExpiresAt) {
			delete(authState.stepup, token)
		}
	}
}

func setAccessCookie(w http.ResponseWriter, token string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     accessCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   accessMaxAgeSec,
	})
}

func setCSRFCookie(w http.ResponseWriter, token string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   accessMaxAgeSec,
	})
}

func clearSessionCookies(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{Name: accessCookieName, Value: "", Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: csrfCookieName, Value: "", Path: "/", HttpOnly: false, Secure: secure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

func isSecureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	xfp := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")))
	return xfp == "https"
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' https://d3js.org; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func authRequired(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := sessionFromRequest(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		r = r.WithContext(withSession(r.Context(), sess))
		next(w, r)
	}
}

func adminRequired(next http.HandlerFunc) http.HandlerFunc {
	return authRequired(func(w http.ResponseWriter, r *http.Request) {
		sess := mustSessionFromContext(r)
		if sess.Role != "admin" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

func withSession(ctx context.Context, sess accessSession) context.Context {
	return context.WithValue(ctx, sessionContextKey, sess)
}

func mustSessionFromContext(r *http.Request) accessSession {
	v := r.Context().Value(sessionContextKey)
	sess, _ := v.(accessSession)
	return sess
}

func requireStateProtection(next http.HandlerFunc) http.HandlerFunc {
	return adminRequired(func(w http.ResponseWriter, r *http.Request) {
		sess := mustSessionFromContext(r)
		if !validateCSRF(r, sess) {
			logAudit("csrf.validation", sess.Username, sess.Role, "denied", map[string]any{"path": r.URL.Path})
			http.Error(w, "csrf validation failed", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

func logAudit(event, username, role, outcome string, details map[string]any) {
	entry := map[string]any{
		"ts":      time.Now().UTC().Format(time.RFC3339Nano),
		"event":   event,
		"user":    username,
		"role":    role,
		"outcome": outcome,
	}
	if details != nil {
		entry["details"] = details
	}
	b, _ := json.Marshal(entry)
	fmt.Printf("[AUDIT] %s\n", string(b))
}

func computeX(username, password string, salt []byte) *big.Int {
	up := hashBytes([]byte(username + ":" + password))
	x := hashBytes(salt, up)
	return bigFromBytes(x)
}

func computeM1(username string, salt []byte, A, B *big.Int, K []byte) []byte {
	hn := hashBytes(padToN(srpN))
	hg := hashBytes(padToN(srpG))
	xor := make([]byte, len(hn))
	for i := range hn {
		xor[i] = hn[i] ^ hg[i]
	}
	hi := hashBytes([]byte(username))
	return hashBytes(xor, hi, salt, padToN(A), padToN(B), K)
}

func computeM2(A *big.Int, M1, K []byte) []byte {
	return hashBytes(padToN(A), M1, K)
}

func padToN(v *big.Int) []byte {
	b := v.Bytes()
	if len(b) >= nBytes {
		return b
	}
	out := make([]byte, nBytes)
	copy(out[nBytes-len(b):], b)
	return out
}

func hashBytes(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	return h.Sum(nil)
}

func bigFromBytes(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}

func randInt(numBytes int) (*big.Int, error) {
	buf := make([]byte, numBytes)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(buf), nil
}

func randToken(numBytes int) (string, error) {
	buf := make([]byte, numBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func mustRandToken(numBytes int) string {
	t, err := randToken(numBytes)
	if err != nil {
		panic(err)
	}
	return t
}

func mustRandBytes(numBytes int) []byte {
	buf := make([]byte, numBytes)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return buf
}

func remoteIP(r *http.Request) string {
	xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func writeDemoCredsFile(username, password string) {
	path := strings.TrimSpace(os.Getenv("SCUDOZI_CREDS_FILE"))
	if path == "" {
		path = "./scudozi-demo-creds.txt"
	}
	content := fmt.Sprintf("username=%s\npassword=%s\n", username, password)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		fmt.Printf("[Scudozi] Failed to write creds file (%s): %v\n", path, err)
		return
	}
	fmt.Printf("[Scudozi] Credentials also written to %s\n", path)
}
