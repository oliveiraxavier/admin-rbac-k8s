package authentik

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestAuthenticateValidatesSignedSessionAndExpiry(t *testing.T) {
	auth := &Authenticator{sessionSecret: []byte("a session signing key with enough entropy")}
	handler := auth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	valid, err := auth.encodeSigned(sessionClaims{ExpiresAt: time.Now().Add(time.Minute).Unix()})
	if err != nil {
		t.Fatalf("encode session: %v", err)
	}
	for _, testCase := range []struct {
		name       string
		value      string
		wantStatus int
	}{
		{name: "valid session", value: valid, wantStatus: http.StatusNoContent},
		{name: "tampered session", value: valid + "x", wantStatus: http.StatusUnauthorized},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/api/v1/tokens", nil)
			request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: testCase.value})
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != testCase.wantStatus {
				t.Fatalf("expected status %d, got %d", testCase.wantStatus, response.Code)
			}
		})
	}

	expired, err := auth.encodeSigned(sessionClaims{ExpiresAt: time.Now().Add(-time.Minute).Unix()})
	if err != nil {
		t.Fatalf("encode expired session: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/tokens", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: expired})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected expired session status %d, got %d", http.StatusUnauthorized, response.Code)
	}
}

func TestLoginUsesStateNonceAndPKCE(t *testing.T) {
	auth := &Authenticator{
		oauthConfig: oauth2.Config{
			ClientID:    "test-client",
			Endpoint:    oauth2.Endpoint{AuthURL: "https://authentik.example/application/o/authorize/"},
			RedirectURL: "https://app.example/auth/callback",
		},
		sessionSecret: []byte("a session signing key with enough entropy"),
		secureCookies: true,
	}
	response := httptest.NewRecorder()
	auth.login(response, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	if response.Code != http.StatusFound {
		t.Fatalf("expected redirect status %d, got %d", http.StatusFound, response.Code)
	}
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect URL: %v", err)
	}
	query := location.Query()
	if query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "" || query.Get("nonce") == "" {
		t.Fatalf("expected PKCE challenge and nonce in authorization request: %v", query)
	}
	var state loginState
	if len(response.Result().Cookies()) != 1 || !auth.decodeSigned(response.Result().Cookies()[0].Value, &state) {
		t.Fatal("expected a signed OIDC state cookie")
	}
	if query.Get("state") != state.State || state.Nonce != query.Get("nonce") {
		t.Fatal("authorization request state and nonce must match the signed state cookie")
	}
	cookie := response.Result().Cookies()[0]
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("expected secure, HttpOnly, SameSite=Lax state cookie, got %#v", cookie)
	}
}

func TestCallbackRejectsMismatchedState(t *testing.T) {
	auth := &Authenticator{sessionSecret: []byte("a session signing key with enough entropy")}
	state, err := auth.encodeSigned(loginState{
		State: "expected", Nonce: "nonce", Verifier: "verifier",
		ExpiresAt: time.Now().Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("encode state: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "/auth/callback?state=attacker&code=code", nil)
	request.AddCookie(&http.Cookie{Name: stateCookieName, Value: state})
	response := httptest.NewRecorder()
	auth.callback(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected mismatched state status %d, got %d", http.StatusBadRequest, response.Code)
	}
}

func TestSessionEndpointReportsAuthentikProvider(t *testing.T) {
	auth := &Authenticator{sessionSecret: []byte("a session signing key with enough entropy")}
	response := httptest.NewRecorder()
	auth.session(response, httptest.NewRequest(http.MethodGet, "/auth/session", nil))
	var session Session
	if err := json.Unmarshal(response.Body.Bytes(), &session); err != nil {
		t.Fatalf("decode session response: %v", err)
	}
	if session.Provider != "authentik" || session.Authenticated {
		t.Fatalf("expected unauthenticated Authentik session, got %#v", session)
	}
}

func TestAllowedGroupRequiresMembership(t *testing.T) {
	if !hasAllowedGroup([]string{"developers", "admins"}, []string{"admins"}) {
		t.Fatal("expected matching group to be authorized")
	}
	if hasAllowedGroup([]string{"developers"}, []string{"admins"}) {
		t.Fatal("expected non-matching group to be rejected")
	}
}

func TestNewRejectsInsecureRemoteIssuer(t *testing.T) {
	_, err := New(t.Context(), Config{
		IssuerURL: "http://authentik.example/application/o/kube-access/",
		ClientID:  "client", ClientSecret: "secret",
		RedirectURL:   "https://app.example/auth/callback",
		SessionSecret: "a session signing key with enough entropy",
	})
	if err == nil {
		t.Fatal("expected non-local HTTP issuer to be rejected")
	}
}

func TestOIDCCallbackCreatesAuthenticatedSession(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	var idToken string
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSONResponse(w, map[string]any{
				"issuer":                                issuer,
				"authorization_endpoint":                issuer + "/authorize",
				"token_endpoint":                        issuer + "/token",
				"jwks_uri":                              issuer + "/jwks",
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
				"token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
			})
		case "/jwks":
			writeJSONResponse(w, map[string]any{"keys": []map[string]string{{
				"kty": "RSA", "kid": "test-key", "use": "sig", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.E)).Bytes()),
			}}})
		case "/token":
			writeJSONResponse(w, map[string]any{
				"access_token": "access-token", "token_type": "Bearer",
				"expires_in": 3600, "id_token": idToken,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	issuer = server.URL

	auth, err := New(context.Background(), Config{
		IssuerURL: issuer, ClientID: "test-client", ClientSecret: "test-secret",
		RedirectURL:   "http://localhost:4200/auth/callback",
		SessionSecret: "a session signing key with enough entropy",
		AllowedGroups: []string{"platform-admins"},
	})
	if err != nil {
		t.Fatalf("create Authentik authenticator: %v", err)
	}

	loginResponse := httptest.NewRecorder()
	auth.login(loginResponse, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	loginURL, err := url.Parse(loginResponse.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse login redirect: %v", err)
	}
	stateCookie := loginResponse.Result().Cookies()[0]
	idToken = signIDToken(t, privateKey, issuer, "test-client", loginURL.Query().Get("nonce"))

	callbackURL := "/auth/callback?code=authorization-code&state=" + url.QueryEscape(loginURL.Query().Get("state"))
	callbackRequest := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	callbackRequest.AddCookie(stateCookie)
	callbackResponse := httptest.NewRecorder()
	auth.callback(callbackResponse, callbackRequest)
	if callbackResponse.Code != http.StatusSeeOther {
		t.Fatalf("expected callback redirect status %d, got %d: %s", http.StatusSeeOther, callbackResponse.Code, callbackResponse.Body.String())
	}

	var sessionCookie *http.Cookie
	for _, cookie := range callbackResponse.Result().Cookies() {
		if cookie.Name == sessionCookieName {
			sessionCookie = cookie
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected callback to set a session cookie")
	}
	sessionRequest := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	sessionRequest.AddCookie(sessionCookie)
	sessionResponse := httptest.NewRecorder()
	auth.session(sessionResponse, sessionRequest)
	var session Session
	if err := json.Unmarshal(sessionResponse.Body.Bytes(), &session); err != nil {
		t.Fatalf("decode session response: %v", err)
	}
	if !session.Authenticated || session.User == nil || session.User.Email != "admin@example.test" {
		t.Fatalf("expected authenticated user session, got %#v", session)
	}
}

func signIDToken(t *testing.T, key *rsa.PrivateKey, issuer, clientID, nonce string) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": "test-key", "typ": "JWT"})
	if err != nil {
		t.Fatalf("encode ID token header: %v", err)
	}
	claims, err := json.Marshal(map[string]any{
		"iss": issuer, "sub": "admin-user", "aud": clientID,
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		"nonce": nonce, "email": "admin@example.test", "name": "Admin",
		"groups": []string{"platform-admins"},
	})
	if err != nil {
		t.Fatalf("encode ID token claims: %v", err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	hash := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatalf("sign ID token: %v", err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func writeJSONResponse(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		panic(err)
	}
}
