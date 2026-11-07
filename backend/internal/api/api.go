package api

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type api struct {
	client     kubernetes.Interface
	adminToken string
	namespaces map[string]struct{}
}

func NewHandler(client kubernetes.Interface, token string, namespaces []string) http.Handler {
	return newAPI(client, token, namespaces).routes()
}

func newAPI(client kubernetes.Interface, token string, namespaces []string) *api {
	allowed := make(map[string]struct{}, len(namespaces))
	for _, namespace := range namespaces {
		allowed[namespace] = struct{}{}
	}
	return &api{client: client, adminToken: token, namespaces: allowed}
}

func (a *api) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /openapi.yaml", openAPIDocument)
	mux.HandleFunc("GET /docs", swaggerUI)
	mux.Handle("GET /api/v1/namespaces", a.authenticate(http.HandlerFunc(a.listNamespaces)))
	mux.Handle("/api/v1/tokens", a.authenticate(http.HandlerFunc(a.collection)))
	mux.Handle("/api/v1/tokens/", a.authenticate(http.HandlerFunc(a.item)))

	return mux
}

func (a *api) listNamespaces(w http.ResponseWriter, _ *http.Request) {
	namespaces := make([]string, 0, len(a.namespaces))
	for namespace := range a.namespaces {
		namespaces = append(namespaces, namespace)
	}
	slices.Sort(namespaces)
	writeJSON(w, http.StatusOK, namespaces)
}

func (a *api) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if provided == r.Header.Get("Authorization") || subtle.ConstantTimeCompare([]byte(provided), []byte(a.adminToken)) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *api) collection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.list(w, r)
	case http.MethodPost:
		a.create(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *api) item(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if (len(parts) != 5 && len(parts) != 6) || parts[0] != "api" || parts[1] != "v1" || parts[2] != "tokens" {
		http.NotFound(w, r)
		return
	}
	namespace, name := parts[3], parts[4]
	if len(parts) == 6 {
		if parts[5] != "issue" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		a.issueToken(w, r, namespace, name)
		return
	}
	if !a.allowedNamespace(namespace) {
		writeError(w, http.StatusNotFound, "identity not found")
		return
	}
	if r.Method == http.MethodPut {
		a.update(w, r, namespace, name)
		return
	}
	if r.Method == http.MethodDelete {
		a.delete(w, r, namespace, name)
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}

func (a *api) list(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	result := make([]identity, 0)
	for namespace := range a.namespaces {
		accounts, err := a.client.CoreV1().ServiceAccounts(namespace).List(ctx, metav1.ListOptions{LabelSelector: managedSelector})
		if err != nil {
			writeKubeError(w, err)
			return
		}
		for _, account := range accounts.Items {
			scopes, err := a.managedScopes(ctx, &account)
			if err != nil {
				writeKubeError(w, err)
				return
			}
			if len(scopes) == 0 {
				continue
			}
			targetNamespaces := make([]string, 0, len(scopes))
			for targetNamespace := range scopes {
				targetNamespaces = append(targetNamespaces, targetNamespace)
			}
			slices.Sort(targetNamespaces)
			permissions := permissionsFromRules(scopes[targetNamespaces[0]].role.Rules)
			result = append(result, identity{
				Name: account.Name, Namespace: namespace, CreatedAt: account.CreationTimestamp,
				Namespaces: targetNamespaces, Permissions: permissions,
			})
		}
	}
	writeJSON(w, http.StatusOK, result)
}

func decodeRequest(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON request")
		return false
	}
	return true
}

func (a *api) issueToken(w http.ResponseWriter, r *http.Request, namespace, name string) {
	if !a.allowedNamespace(namespace) {
		writeError(w, http.StatusNotFound, "identity not found")
		return
	}
	var request struct {
		TTLSeconds *int64 `json:"ttlSeconds"`
	}
	if !decodeRequest(w, r, &request) {
		return
	}
	ttlSeconds := tokenTTL(request.TTLSeconds)
	if err := validateTokenTTL(ttlSeconds); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	account, err := a.client.CoreV1().ServiceAccounts(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil || account.Labels[managedLabel] != managedValue {
		writeError(w, http.StatusNotFound, "identity not found")
		return
	}
	scopes, err := a.managedScopes(ctx, account)
	if err != nil {
		writeKubeError(w, err)
		return
	}
	if len(scopes) == 0 {
		writeError(w, http.StatusNotFound, "managed role not found")
		return
	}
	result, err := a.issue(ctx, namespace, name, ttlSeconds)
	if err != nil {
		writeKubeError(w, err)
		return
	}
	namespaces := make([]string, 0, len(scopes))
	for targetNamespace := range scopes {
		namespaces = append(namespaces, targetNamespace)
	}
	slices.Sort(namespaces)
	result.Identity = identity{Name: name, Namespace: namespace, Namespaces: namespaces, CreatedAt: account.CreationTimestamp, Permissions: permissionsFromRules(scopes[namespaces[0]].role.Rules)}
	writeJSON(w, http.StatusCreated, result)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
