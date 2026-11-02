package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestAuthenticationRequired(t *testing.T) {
	app := newAPI(fake.NewSimpleClientset(), "01234567890123456789012345678901", []string{"team-a"})
	request := httptest.NewRequest(http.MethodGet, "/api/v1/tokens", nil)
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, response.Code)
	}
}

func TestPermissionValidationRejectsEscalation(t *testing.T) {
	app := newAPI(fake.NewSimpleClientset(), "01234567890123456789012345678901", []string{"team-a"})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/tokens", strings.NewReader(`{"name":"viewer","namespace":"team-a","ttlSeconds":3600,"permissions":[{"apiGroup":"","resource":"secrets","verbs":["get"]}]}`))
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, response.Code)
	}
}

func TestPermissionValidationAllowsDeletePodsOnly(t *testing.T) {
	app := newAPI(fake.NewSimpleClientset(), "01234567890123456789012345678901", []string{"team-a"})
	response := httptest.NewRecorder()
	if !app.validate(response, "operator", "team-a", 3600, []permission{{APIGroup: "", Resource: "pods", Verbs: []string{"delete"}}}) {
		t.Fatalf("expected delete pods to be allowed, got %d: %s", response.Code, response.Body.String())
	}

	for _, resource := range []string{"services", "pods/log", "pods/exec"} {
		response = httptest.NewRecorder()
		if app.validate(response, "operator", "team-a", 3600, []permission{{APIGroup: "", Resource: resource, Verbs: []string{"delete"}}}) {
			t.Errorf("expected delete %s to be rejected", resource)
		}
	}
}

func TestPermissionValidationAllowsPodLogsOnlyWithGet(t *testing.T) {
	app := newAPI(fake.NewSimpleClientset(), "01234567890123456789012345678901", []string{"team-a"})
	response := httptest.NewRecorder()
	if !app.validate(response, "viewer", "team-a", 3600, []permission{{APIGroup: "", Resource: "pods/log", Verbs: []string{"get"}}}) {
		t.Fatalf("expected get pods/log to be allowed, got %d: %s", response.Code, response.Body.String())
	}

	response = httptest.NewRecorder()
	if app.validate(response, "viewer", "team-a", 3600, []permission{{APIGroup: "", Resource: "pods/log", Verbs: []string{"list"}}}) {
		t.Fatal("expected list pods/log to be rejected")
	}
}

func TestPermissionValidationAllowsPodExecOnlyWithCreate(t *testing.T) {
	app := newAPI(fake.NewSimpleClientset(), "01234567890123456789012345678901", []string{"team-a"})
	response := httptest.NewRecorder()
	if !app.validate(response, "operator", "team-a", 3600, []permission{{APIGroup: "", Resource: "pods/exec", Verbs: []string{"create"}}}) {
		t.Fatalf("expected create pods/exec to be allowed, got %d: %s", response.Code, response.Body.String())
	}

	for _, testCase := range []struct {
		resource string
		verb     string
	}{
		{resource: "pods/exec", verb: "get"},
		{resource: "pods", verb: "create"},
	} {
		response = httptest.NewRecorder()
		if app.validate(response, "operator", "team-a", 3600, []permission{{APIGroup: "", Resource: testCase.resource, Verbs: []string{testCase.verb}}}) {
			t.Errorf("expected %s on %s to be rejected", testCase.verb, testCase.resource)
		}
	}
}

func TestSecretPermissionsSupportNamedAndAllSecretsModes(t *testing.T) {
	app := newAPI(fake.NewSimpleClientset(), "01234567890123456789012345678901", []string{"team-a"})
	secretPermission := permission{APIGroup: "", Resource: "secrets", Verbs: []string{"get"}, ResourceNames: []string{"db-credentials", "registry-auth"}}
	response := httptest.NewRecorder()
	if !app.validate(response, "viewer", "team-a", 3600, []permission{secretPermission}) {
		t.Fatalf("expected named Secret get to be allowed, got %d: %s", response.Code, response.Body.String())
	}

	secretPermission.Verbs = []string{"get", "list", "watch"}
	secretPermission.ResourceNames = nil
	response = httptest.NewRecorder()
	if !app.validate(response, "viewer", "team-a", 3600, []permission{secretPermission}) {
		t.Fatalf("expected all-Secret read permissions to be allowed, got %d: %s", response.Code, response.Body.String())
	}

	rules := rulesFromPermissions([]permission{secretPermission})
	if len(rules) != 1 || len(rules[0].ResourceNames) != 0 {
		t.Fatalf("expected unrestricted Secret rule, got %#v", rules)
	}

	secretPermission.ResourceNames = []string{"db-credentials"}
	response = httptest.NewRecorder()
	if app.validate(response, "viewer", "team-a", 3600, []permission{secretPermission}) {
		t.Fatal("expected named Secret list/watch to be rejected")
	}

	secretPermission.Verbs = []string{"get"}
	secretPermission.ResourceNames = []string{"*"}
	response = httptest.NewRecorder()
	if app.validate(response, "viewer", "team-a", 3600, []permission{secretPermission}) {
		t.Fatal("expected wildcard Secret name to be rejected")
	}

	secretPermission.ResourceNames = []string{"db-credentials"}
	secretPermission.Verbs = []string{"watch"}
	response = httptest.NewRecorder()
	if app.validate(response, "viewer", "team-a", 3600, []permission{secretPermission}) {
		t.Fatal("expected Secret watch to be rejected")
	}

	secretPermission.Resource = "pods"
	secretPermission.Verbs = []string{"get"}
	response = httptest.NewRecorder()
	if app.validate(response, "viewer", "team-a", 3600, []permission{secretPermission}) {
		t.Fatal("expected resourceNames on pods to be rejected")
	}
}

func TestSecretResourceNamesSurviveRoleRoundTrip(t *testing.T) {
	want := []string{"db-credentials", "registry-auth"}
	rules := rulesFromPermissions([]permission{{APIGroup: "", Resource: "secrets", Verbs: []string{"get"}, ResourceNames: want}})
	if len(rules) != 1 || strings.Join(rules[0].ResourceNames, ",") != strings.Join(want, ",") {
		t.Fatalf("expected named Secret rule, got %#v", rules)
	}
	got := permissionsFromRules(rules)
	if len(got) != 1 || strings.Join(got[0].ResourceNames, ",") != strings.Join(want, ",") {
		t.Fatalf("expected resource names after round trip, got %#v", got)
	}
}

func TestTokenTTLAllowsOneYearAndRejectsMore(t *testing.T) {
	app := newAPI(fake.NewSimpleClientset(), "01234567890123456789012345678901", []string{"team-a"})
	permissions := []permission{{APIGroup: "", Resource: "pods", Verbs: []string{"get"}}}
	response := httptest.NewRecorder()
	if !app.validate(response, "viewer", "team-a", maximumTTL, permissions) {
		t.Fatalf("expected one-year TTL to be allowed, got %d: %s", response.Code, response.Body.String())
	}

	response = httptest.NewRecorder()
	if app.validate(response, "viewer", "team-a", maximumTTL+1, permissions) {
		t.Fatal("expected TTL beyond one year to be rejected")
	}
}

func TestOmittedTokenTTLDefaultsToOneYear(t *testing.T) {
	if ttl := tokenTTL(nil); ttl != maximumTTL {
		t.Fatalf("expected omitted TTL to default to %d seconds, got %d", maximumTTL, ttl)
	}
	requested := int64(3600)
	if ttl := tokenTTL(&requested); ttl != requested {
		t.Fatalf("expected explicit TTL %d seconds, got %d", requested, ttl)
	}
}

func TestIdentityCanHaveRoleBindingsInMultipleNamespaces(t *testing.T) {
	client := fake.NewSimpleClientset()
	app := newAPI(client, "01234567890123456789012345678901", []string{"identity-ns", "team-a", "team-b"})
	permissions := []permission{{APIGroup: "", Resource: "pods", Verbs: []string{"get", "list"}}}
	account := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "viewer", Namespace: "identity-ns"}}

	for _, namespace := range []string{"team-a", "team-b"} {
		if _, _, err := app.createScope(context.Background(), account.Name, account.Namespace, namespace, permissions); err != nil {
			t.Fatalf("create scope in %s: %v", namespace, err)
		}
	}

	scopes, err := app.managedScopes(context.Background(), account)
	if err != nil {
		t.Fatalf("list managed scopes: %v", err)
	}
	if len(scopes) != 2 {
		t.Fatalf("expected 2 namespace scopes, got %d", len(scopes))
	}
	for _, namespace := range []string{"team-a", "team-b"} {
		binding := scopes[namespace].binding
		if binding.Namespace != namespace || binding.Subjects[0].Namespace != account.Namespace {
			t.Errorf("unexpected binding in %s: %#v", namespace, binding)
		}
	}
}

func TestUpdateAndDeleteIdentityAcrossNamespaces(t *testing.T) {
	account := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{
		Name: "viewer", Namespace: "identity-ns", Labels: map[string]string{managedLabel: managedValue},
	}}
	client := fake.NewSimpleClientset(account)
	app := newAPI(client, "01234567890123456789012345678901", []string{"identity-ns", "team-a", "team-b"})
	permissions := []permission{{APIGroup: "", Resource: "pods", Verbs: []string{"get"}}}
	for _, namespace := range []string{"team-a", "team-b"} {
		if _, _, err := app.createScope(context.Background(), account.Name, account.Namespace, namespace, permissions); err != nil {
			t.Fatalf("create scope in %s: %v", namespace, err)
		}
	}

	request := httptest.NewRequest(http.MethodPut, "/api/v1/tokens/identity-ns/viewer", strings.NewReader(`{"targetNamespaces":["team-b"],"permissions":[{"apiGroup":"","resource":"pods","verbs":["get","list"]}]}`))
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("update returned status %d: %s", response.Code, response.Body.String())
	}
	if _, err := client.RbacV1().RoleBindings("team-a").Get(context.Background(), scopedBindingName("viewer", "identity-ns"), metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("expected team-a binding to be removed, got err=%v", err)
	}
	updatedRole, err := client.RbacV1().Roles("team-b").Get(context.Background(), scopedRoleName("viewer", "identity-ns"), metav1.GetOptions{})
	if err != nil || len(updatedRole.Rules[0].Verbs) != 2 {
		t.Fatalf("expected team-b role permissions to be updated, role=%#v err=%v", updatedRole, err)
	}

	request = httptest.NewRequest(http.MethodDelete, "/api/v1/tokens/identity-ns/viewer", nil)
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	response = httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("delete returned status %d: %s", response.Code, response.Body.String())
	}
	if _, err := client.CoreV1().ServiceAccounts("identity-ns").Get(context.Background(), "viewer", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("expected ServiceAccount to be deleted, got err=%v", err)
	}
}
