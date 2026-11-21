package authentik

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	sessionCookieName = "kubeaccess_session"
	stateCookieName   = "kubeaccess_oidc_state"
	sessionDuration   = 8 * time.Hour
	stateDuration     = 10 * time.Minute
)

type Config struct {
	IssuerURL     string
	ClientID      string
	ClientSecret  string
	RedirectURL   string
	SessionSecret string
	AllowedGroups []string
}

type User struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
}

type Session struct {
	Provider      string `json:"provider"`
	Authenticated bool   `json:"authenticated"`
	User          *User  `json:"user,omitempty"`
}

type sessionClaims struct {
	User      User  `json:"user"`
	ExpiresAt int64 `json:"exp"`
}

type loginState struct {
	State     string `json:"state"`
	Nonce     string `json:"nonce"`
	Verifier  string `json:"verifier"`
	ExpiresAt int64  `json:"exp"`
}

type Authenticator struct {
	oauthConfig   oauth2.Config
	verifier      *oidc.IDTokenVerifier
	sessionSecret []byte
	allowedGroups []string
	secureCookies bool
}

func New(ctx context.Context, config Config) (*Authenticator, error) {
	if config.IssuerURL == "" || config.ClientID == "" || config.ClientSecret == "" || config.RedirectURL == "" {
		return nil, errors.New("authentik issuer, client ID, client secret, and redirect URL are required")
	}
	if len(config.SessionSecret) < 32 {
		return nil, errors.New("AUTHENTIK_SESSION_SECRET must contain at least 32 characters")
	}
	issuerURL, err := url.Parse(config.IssuerURL)
	if err != nil || issuerURL.Host == "" || issuerURL.User != nil || issuerURL.RawQuery != "" ||
		issuerURL.Fragment != "" || (issuerURL.Scheme != "https" && issuerURL.Scheme != "http") {
		return nil, errors.New("authentik issuer URL must be an absolute HTTP or HTTPS URL without query or fragment")
	}
	if issuerURL.Scheme == "http" && issuerURL.Hostname() != "localhost" && issuerURL.Hostname() != "127.0.0.1" {
		return nil, errors.New("authentik issuer URL must use HTTPS except on localhost")
	}
	redirectURL, err := url.Parse(config.RedirectURL)
	if err != nil || redirectURL.Host == "" || (redirectURL.Scheme != "https" && redirectURL.Scheme != "http") {
		return nil, errors.New("authentik redirect URL must be an absolute HTTP or HTTPS URL")
	}
	if redirectURL.Scheme == "http" && redirectURL.Hostname() != "localhost" && redirectURL.Hostname() != "127.0.0.1" {
		return nil, errors.New("authentik redirect URL must use HTTPS except on localhost")
	}
	providerContext := context.WithValue(context.WithoutCancel(ctx), oauth2.HTTPClient, &http.Client{Timeout: 15 * time.Second})
	provider, err := oidc.NewProvider(providerContext, config.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("discover Authentik OIDC provider: %w", err)
	}
	endpoint := provider.Endpoint()
	if err := validateEndpoint(endpoint.AuthURL); err != nil {
		return nil, fmt.Errorf("invalid Authentik authorization endpoint: %w", err)
	}
	if err := validateEndpoint(endpoint.TokenURL); err != nil {
		return nil, fmt.Errorf("invalid Authentik token endpoint: %w", err)
	}

	return &Authenticator{
		oauthConfig: oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			Endpoint:     endpoint,
			RedirectURL:  config.RedirectURL,
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
		verifier:      provider.Verifier(&oidc.Config{ClientID: config.ClientID}),
		sessionSecret: []byte(config.SessionSecret),
		allowedGroups: slices.Clone(config.AllowedGroups),
		secureCookies: redirectURL.Scheme == "https",
	}, nil
}

func (a *Authenticator) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/login", a.login)
	mux.HandleFunc("GET /auth/callback", a.callback)
	mux.HandleFunc("GET /auth/logout", a.logout)
	mux.HandleFunc("GET /auth/session", a.session)
}

func (a *Authenticator) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			writeUnauthorized(w)
			return
		}
		var claims sessionClaims
		if !a.decodeSigned(cookie.Value, &claims) || claims.ExpiresAt <= time.Now().Unix() {
			writeUnauthorized(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *Authenticator) login(w http.ResponseWriter, r *http.Request) {
	state, err := randomString(32)
	if err != nil {
		http.Error(w, "could not start authentication", http.StatusInternalServerError)
		return
	}
	nonce, err := randomString(32)
	if err != nil {
		http.Error(w, "could not start authentication", http.StatusInternalServerError)
		return
	}
	verifier, err := randomString(32)
	if err != nil {
		http.Error(w, "could not start authentication", http.StatusInternalServerError)
		return
	}
	payload := loginState{State: state, Nonce: nonce, Verifier: verifier, ExpiresAt: time.Now().Add(stateDuration).Unix()}
	value, err := a.encodeSigned(payload)
	if err != nil {
		http.Error(w, "could not start authentication", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: stateCookieName, Value: value, Path: "/auth/callback", MaxAge: int(stateDuration.Seconds()),
		HttpOnly: true, Secure: a.secureCookies, SameSite: http.SameSiteLaxMode,
	})
	challenge := base64.RawURLEncoding.EncodeToString(sha256Bytes(verifier))
	http.Redirect(w, r, a.oauthConfig.AuthCodeURL(state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	), http.StatusFound)
}

func (a *Authenticator) callback(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: stateCookieName, Value: "", Path: "/auth/callback", MaxAge: -1,
		HttpOnly: true, Secure: a.secureCookies, SameSite: http.SameSiteLaxMode,
	})
	if providerError := r.URL.Query().Get("error"); providerError != "" {
		http.Error(w, "Authentik authentication was not completed", http.StatusUnauthorized)
		return
	}
	cookie, err := r.Cookie(stateCookieName)
	if err != nil {
		http.Error(w, "authentication state is missing or expired", http.StatusBadRequest)
		return
	}
	var state loginState
	if !a.decodeSigned(cookie.Value, &state) || state.ExpiresAt <= time.Now().Unix() ||
		subtle.ConstantTimeCompare([]byte(state.State), []byte(r.URL.Query().Get("state"))) != 1 {
		http.Error(w, "authentication state is invalid or expired", http.StatusBadRequest)
		return
	}
	exchangeContext := context.WithValue(r.Context(), oauth2.HTTPClient, &http.Client{Timeout: 15 * time.Second})
	token, err := a.oauthConfig.Exchange(exchangeContext, r.URL.Query().Get("code"), oauth2.VerifierOption(state.Verifier))
	if err != nil {
		http.Error(w, "Authentik token exchange failed", http.StatusUnauthorized)
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "Authentik response did not contain an ID token", http.StatusUnauthorized)
		return
	}
	idToken, err := a.verifier.Verify(r.Context(), rawIDToken)
	if err != nil || idToken.Nonce != state.Nonce {
		http.Error(w, "Authentik ID token is invalid", http.StatusUnauthorized)
		return
	}
	var claims struct {
		Email  string   `json:"email"`
		Name   string   `json:"name"`
		Groups []string `json:"groups"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "Authentik ID token claims are invalid", http.StatusUnauthorized)
		return
	}
	if len(a.allowedGroups) > 0 && !hasAllowedGroup(claims.Groups, a.allowedGroups) {
		http.Error(w, "user is not authorized to access this application", http.StatusForbidden)
		return
	}
	expiresAt := time.Now().Add(sessionDuration)
	if idToken.Expiry.Before(expiresAt) {
		expiresAt = idToken.Expiry
	}
	value, err := a.encodeSigned(sessionClaims{
		User:      User{Name: claims.Name, Email: claims.Email},
		ExpiresAt: expiresAt.Unix(),
	})
	if err != nil {
		http.Error(w, "could not create authenticated session", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: value, Path: "/", Expires: expiresAt,
		HttpOnly: true, Secure: a.secureCookies, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *Authenticator) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: a.secureCookies, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *Authenticator) session(w http.ResponseWriter, r *http.Request) {
	result := Session{Provider: "authentik"}
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		var claims sessionClaims
		if a.decodeSigned(cookie.Value, &claims) && claims.ExpiresAt > time.Now().Unix() {
			result.Authenticated = true
			result.User = &claims.User
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		http.Error(w, "could not encode session response", http.StatusInternalServerError)
	}
}

func (a *Authenticator) encodeSigned(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, a.sessionSecret)
	_, _ = mac.Write([]byte(encoded))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return encoded + "." + signature, nil
}

func (a *Authenticator) decodeSigned(value string, target any) bool {
	encoded, signature, ok := strings.Cut(value, ".")
	if !ok {
		return false
	}
	provided, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, a.sessionSecret)
	_, _ = mac.Write([]byte(encoded))
	if !hmac.Equal(provided, mac.Sum(nil)) {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || json.Unmarshal(payload, target) != nil {
		return false
	}
	return true
}

func hasAllowedGroup(userGroups, allowedGroups []string) bool {
	for _, group := range userGroups {
		if slices.Contains(allowedGroups, group) {
			return true
		}
	}
	return false
}

func validateEndpoint(value string) error {
	endpoint, err := url.Parse(value)
	if err != nil || endpoint.Host == "" || endpoint.User != nil ||
		(endpoint.Scheme != "https" && endpoint.Scheme != "http") {
		return errors.New("must be an absolute HTTP or HTTPS URL")
	}
	if endpoint.Scheme == "http" && endpoint.Hostname() != "localhost" && endpoint.Hostname() != "127.0.0.1" {
		return errors.New("must use HTTPS except on localhost")
	}
	return nil
}

func randomString(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func sha256Bytes(value string) []byte {
	sum := sha256.Sum256([]byte(value))
	return sum[:]
}

func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
}
