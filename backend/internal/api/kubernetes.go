package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"slices"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	managedLabel    = "app.kubernetes.io/managed-by"
	managedValue    = "k8s-access-manager"
	roleAnnotation  = "k8s-access-manager/role"
	managedSelector = managedLabel + "=" + managedValue
)

func (a *api) allowedNamespace(namespace string) bool {
	_, ok := a.namespaces[namespace]
	return ok
}

type managedScope struct {
	binding *rbacv1.RoleBinding
	role    *rbacv1.Role
}

func scopedObjectName(name, identityNamespace, suffix string) string {
	hash := sha256.Sum256([]byte(identityNamespace + "/" + name))
	hashText := hex.EncodeToString(hash[:4])
	maxPrefix := 63 - len(hashText) - len(suffix) - 2
	if len(name) > maxPrefix {
		name = name[:maxPrefix]
	}
	return name + "-" + hashText + "-" + suffix
}

func scopedRoleName(name, identityNamespace string) string {
	return scopedObjectName(name, identityNamespace, "access")
}

func scopedBindingName(name, identityNamespace string) string {
	return scopedObjectName(name, identityNamespace, "binding")
}

func (a *api) managedScopes(ctx context.Context, account *corev1.ServiceAccount) (map[string]managedScope, error) {
	result := make(map[string]managedScope)
	for namespace := range a.namespaces {
		bindings, err := a.client.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{LabelSelector: managedSelector})
		if err != nil {
			return nil, err
		}
		for i := range bindings.Items {
			binding := &bindings.Items[i]
			if binding.RoleRef.Kind != "Role" || binding.RoleRef.APIGroup != rbacv1.GroupName {
				continue
			}
			matches := false
			for _, subject := range binding.Subjects {
				if subject.Kind == rbacv1.ServiceAccountKind && subject.Name == account.Name && subject.Namespace == account.Namespace {
					matches = true
					break
				}
			}
			if !matches {
				continue
			}
			role, err := a.client.RbacV1().Roles(namespace).Get(ctx, binding.RoleRef.Name, metav1.GetOptions{})
			if apierrors.IsNotFound(err) || (err == nil && role.Labels[managedLabel] != managedValue) {
				continue
			}
			if err != nil {
				return nil, err
			}
			result[namespace] = managedScope{binding: binding.DeepCopy(), role: role}
		}
	}
	return result, nil
}

func (a *api) create(w http.ResponseWriter, r *http.Request) {
	var request createRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	ttlSeconds := tokenTTL(request.TTLSeconds)
	if !a.validate(w, request.Name, request.Namespace, ttlSeconds, request.Permissions) || !a.validateTargetNamespaces(w, request.TargetNamespaces) {
		return
	}
	ctx := r.Context()
	labels := map[string]string{managedLabel: managedValue}
	account, err := a.client.CoreV1().ServiceAccounts(request.Namespace).Create(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: request.Name, Labels: labels, Annotations: map[string]string{roleAnnotation: scopedRoleName(request.Name, request.Namespace)}},
	}, metav1.CreateOptions{})
	if err != nil {
		writeKubeError(w, err)
		return
	}

	createdScopes := make([]string, 0, len(request.TargetNamespaces))
	for _, targetNamespace := range request.TargetNamespaces {
		if _, _, err = a.createScope(ctx, request.Name, request.Namespace, targetNamespace, request.Permissions); err != nil {
			for _, createdNamespace := range createdScopes {
				a.deleteCreatedScope(ctx, request.Name, request.Namespace, createdNamespace)
			}
			_ = a.client.CoreV1().ServiceAccounts(request.Namespace).Delete(ctx, account.Name, metav1.DeleteOptions{})
			writeKubeError(w, err)
			return
		}
		createdScopes = append(createdScopes, targetNamespace)
	}
	result, err := a.issue(ctx, request.Namespace, request.Name, ttlSeconds)
	if err != nil {
		for _, targetNamespace := range createdScopes {
			a.deleteCreatedScope(ctx, request.Name, request.Namespace, targetNamespace)
		}
		_ = a.client.CoreV1().ServiceAccounts(request.Namespace).Delete(ctx, account.Name, metav1.DeleteOptions{})
		writeKubeError(w, err)
		return
	}
	result.Identity = identity{Name: account.Name, Namespace: request.Namespace, Namespaces: request.TargetNamespaces, CreatedAt: account.CreationTimestamp, Permissions: request.Permissions}
	writeJSON(w, http.StatusCreated, result)
}

func tokenTTL(requested *int64) int64 {
	if requested == nil {
		return maximumTTL
	}
	return *requested
}

func (a *api) createScope(ctx context.Context, name, identityNamespace, targetNamespace string, permissions []permission) (*rbacv1.RoleBinding, *rbacv1.Role, error) {
	labels := map[string]string{managedLabel: managedValue}
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: scopedRoleName(name, identityNamespace), Namespace: targetNamespace, Labels: labels},
		Rules:      rulesFromPermissions(permissions),
	}
	createdRole, err := a.client.RbacV1().Roles(targetNamespace).Create(ctx, role, metav1.CreateOptions{})
	if err != nil {
		return nil, nil, err
	}
	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: scopedBindingName(name, identityNamespace), Namespace: targetNamespace, Labels: labels},
		Subjects:   []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: name, Namespace: identityNamespace}},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: createdRole.Name},
	}
	createdBinding, err := a.client.RbacV1().RoleBindings(targetNamespace).Create(ctx, binding, metav1.CreateOptions{})
	if err != nil {
		_ = a.client.RbacV1().Roles(targetNamespace).Delete(ctx, createdRole.Name, metav1.DeleteOptions{})
		return nil, nil, err
	}
	return createdBinding, createdRole, nil
}

func (a *api) deleteCreatedScope(ctx context.Context, name, identityNamespace, targetNamespace string) {
	_ = a.client.RbacV1().RoleBindings(targetNamespace).Delete(ctx, scopedBindingName(name, identityNamespace), metav1.DeleteOptions{})
	_ = a.client.RbacV1().Roles(targetNamespace).Delete(ctx, scopedRoleName(name, identityNamespace), metav1.DeleteOptions{})
}

func (a *api) update(w http.ResponseWriter, r *http.Request, namespace, name string) {
	var request struct {
		TargetNamespaces []string     `json:"targetNamespaces"`
		Permissions      []permission `json:"permissions"`
	}
	if !decodeRequest(w, r, &request) || !a.validate(w, name, namespace, maximumTTL, request.Permissions) || !a.validateTargetNamespaces(w, request.TargetNamespaces) {
		return
	}
	ctx := r.Context()
	account, err := a.client.CoreV1().ServiceAccounts(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil || account.Labels[managedLabel] != managedValue {
		writeError(w, http.StatusNotFound, "identity not found")
		return
	}
	existing, err := a.managedScopes(ctx, account)
	if err != nil {
		writeKubeError(w, err)
		return
	}
	if len(existing) == 0 {
		writeError(w, http.StatusNotFound, "managed role bindings not found")
		return
	}
	targetSet := make(map[string]struct{}, len(request.TargetNamespaces))
	created := make([]string, 0)
	for _, targetNamespace := range request.TargetNamespaces {
		targetSet[targetNamespace] = struct{}{}
		if _, ok := existing[targetNamespace]; ok {
			continue
		}
		if _, _, err = a.createScope(ctx, name, namespace, targetNamespace, request.Permissions); err != nil {
			for _, createdNamespace := range created {
				a.deleteCreatedScope(ctx, name, namespace, createdNamespace)
			}
			writeKubeError(w, err)
			return
		}
		created = append(created, targetNamespace)
	}

	updated := make([]*rbacv1.Role, 0)
	for _, targetNamespace := range request.TargetNamespaces {
		scope, ok := existing[targetNamespace]
		if !ok {
			continue
		}
		previous := scope.role.DeepCopy()
		scope.role.Rules = rulesFromPermissions(request.Permissions)
		if _, err = a.client.RbacV1().Roles(targetNamespace).Update(ctx, scope.role, metav1.UpdateOptions{}); err != nil {
			for _, oldRole := range updated {
				_, _ = a.client.RbacV1().Roles(oldRole.Namespace).Update(ctx, oldRole, metav1.UpdateOptions{})
			}
			for _, createdNamespace := range created {
				a.deleteCreatedScope(ctx, name, namespace, createdNamespace)
			}
			writeKubeError(w, err)
			return
		}
		updated = append(updated, previous)
	}
	for targetNamespace, scope := range existing {
		if _, keep := targetSet[targetNamespace]; keep {
			continue
		}
		if err = a.deleteManagedScope(ctx, targetNamespace, scope); err != nil {
			writeKubeError(w, err)
			return
		}
	}
	slices.Sort(request.TargetNamespaces)
	writeJSON(w, http.StatusOK, identity{Name: name, Namespace: namespace, Namespaces: request.TargetNamespaces, CreatedAt: account.CreationTimestamp, Permissions: request.Permissions})
}

func (a *api) delete(w http.ResponseWriter, r *http.Request, namespace, name string) {
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
	for targetNamespace, scope := range scopes {
		if err = a.deleteManagedScope(ctx, targetNamespace, scope); err != nil {
			writeKubeError(w, err)
			return
		}
	}
	if err = a.client.CoreV1().ServiceAccounts(namespace).Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		writeKubeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) deleteManagedScope(ctx context.Context, namespace string, scope managedScope) error {
	if err := a.client.RbacV1().RoleBindings(namespace).Delete(ctx, scope.binding.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	bindings, err := a.client.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, binding := range bindings.Items {
		if binding.RoleRef.Kind == "Role" && binding.RoleRef.Name == scope.role.Name {
			return nil
		}
	}
	if err := a.client.RbacV1().Roles(namespace).Delete(ctx, scope.role.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return nil
}

func (a *api) issue(ctx context.Context, namespace, name string, ttl int64) (tokenResponse, error) {
	response, err := a.client.CoreV1().ServiceAccounts(namespace).CreateToken(ctx, name, &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{ExpirationSeconds: &ttl},
	}, metav1.CreateOptions{})
	if err != nil {
		return tokenResponse{}, err
	}
	return tokenResponse{Token: response.Status.Token, Expires: response.Status.ExpirationTimestamp.Format(time.RFC3339)}, nil
}

func rulesFromPermissions(permissions []permission) []rbacv1.PolicyRule {
	rules := make([]rbacv1.PolicyRule, 0, len(permissions))
	for _, item := range permissions {
		rules = append(rules, rbacv1.PolicyRule{APIGroups: []string{item.APIGroup}, Resources: []string{item.Resource}, Verbs: item.Verbs, ResourceNames: item.ResourceNames})
	}
	return rules
}

func permissionsFromRules(rules []rbacv1.PolicyRule) []permission {
	result := make([]permission, 0, len(rules))
	for _, rule := range rules {
		for _, group := range rule.APIGroups {
			for _, resource := range rule.Resources {
				result = append(result, permission{APIGroup: group, Resource: resource, Verbs: rule.Verbs, ResourceNames: rule.ResourceNames})
			}
		}
	}
	return result
}

func writeKubeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	if apierrors.IsAlreadyExists(err) {
		status = http.StatusConflict
	} else if apierrors.IsForbidden(err) {
		status = http.StatusForbidden
	} else if apierrors.IsNotFound(err) {
		status = http.StatusNotFound
	}
	writeError(w, status, fmt.Sprintf("Kubernetes API request failed: %v", err))
}
