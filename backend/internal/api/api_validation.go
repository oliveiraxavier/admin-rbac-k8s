package api

import "net/http"

func (a *api) validate(w http.ResponseWriter, name, namespace string, ttl int64, permissions []permission) bool {
	if err := validateIdentity(name, namespace, ttl, permissions, a.namespaces); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return false
	}
	return true
}

func (a *api) validateTargetNamespaces(w http.ResponseWriter, namespaces []string) bool {
	if err := validateNamespaceTargets(namespaces, a.namespaces); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return false
	}
	return true
}
