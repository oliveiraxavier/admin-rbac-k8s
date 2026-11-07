package api

import (
	"errors"
	"regexp"
	"slices"

	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	minimumTTL = int64(600)
	maximumTTL = int64(365 * 24 * 60 * 60)
)

var identityNamePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

var allowedResources = map[string][]string{
	"":      {"pods", "pods/log", "pods/exec", "secrets", "services"},
	"apps":  {"deployments", "replicasets"},
	"batch": {"jobs", "cronjobs"},
}

func validateIdentity(name, namespace string, ttl int64, permissions []permission, allowedNamespaces map[string]struct{}) error {
	if _, ok := allowedNamespaces[namespace]; !ok {
		return errors.New("namespace is not allowed")
	}
	if len(name) > 50 || !identityNamePattern.MatchString(name) {
		return errors.New("name must be a DNS label of at most 50 characters")
	}
	if err := validateTokenTTL(ttl); err != nil {
		return err
	}
	if len(permissions) == 0 || len(permissions) > 20 {
		return errors.New("provide between 1 and 20 permissions")
	}
	for _, item := range permissions {
		resources, ok := allowedResources[item.APIGroup]
		if !ok || !slices.Contains(resources, item.Resource) || len(item.Verbs) == 0 {
			return errors.New("permission contains a resource outside the allowlist")
		}
		if item.Resource == "secrets" {
			if len(item.ResourceNames) > 0 {
				if len(item.Verbs) != 1 || item.Verbs[0] != "get" {
					return errors.New("named Secrets only support get")
				}
				if len(item.ResourceNames) > 50 {
					return errors.New("select at most 50 Secret names")
				}
				seenNames := make(map[string]struct{}, len(item.ResourceNames))
				for _, name := range item.ResourceNames {
					if len(validation.IsDNS1123Subdomain(name)) > 0 {
						return errors.New("Secret names must be valid DNS subdomains")
					}
					if _, exists := seenNames[name]; exists {
						return errors.New("Secret names must be unique")
					}
					seenNames[name] = struct{}{}
				}
			}
		} else if len(item.ResourceNames) > 0 {
			return errors.New("resourceNames are only supported for Secrets")
		}
		for _, verb := range item.Verbs {
			if verb == "delete" {
				if item.Resource != "pods" {
					return errors.New("delete is only allowed for pods")
				}
				continue
			}
			if item.Resource == "pods/exec" {
				if verb != "create" {
					return errors.New("pods/exec only supports the create verb")
				}
				continue
			}
			if !slices.Contains([]string{"get", "list", "watch"}, verb) {
				return errors.New("only get, list, watch, and delete pods verbs are allowed")
			}
			if item.Resource == "pods/log" && verb != "get" {
				return errors.New("pods/log only supports the get verb")
			}
		}
	}
	return nil
}

func validateNamespaceTargets(namespaces []string, allowedNamespaces map[string]struct{}) error {
	if len(namespaces) == 0 || len(namespaces) > len(allowedNamespaces) {
		return errors.New("select at least one allowed namespace")
	}
	seen := make(map[string]struct{}, len(namespaces))
	for _, namespace := range namespaces {
		if _, ok := allowedNamespaces[namespace]; !ok {
			return errors.New("namespace is not allowed")
		}
		if _, exists := seen[namespace]; exists {
			return errors.New("target namespaces must be unique")
		}
		seen[namespace] = struct{}{}
	}
	return nil
}

func validateTokenTTL(ttl int64) error {
	if ttl < minimumTTL || ttl > maximumTTL {
		return errors.New("ttlSeconds must be between 600 and 31536000")
	}
	return nil
}
