package api

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

type permission struct {
	APIGroup      string   `json:"apiGroup"`
	Resource      string   `json:"resource"`
	Verbs         []string `json:"verbs"`
	ResourceNames []string `json:"resourceNames,omitempty"`
}

type identity struct {
	Name        string       `json:"name"`
	Namespace   string       `json:"namespace"`
	Namespaces  []string     `json:"namespaces"`
	CreatedAt   metav1.Time  `json:"createdAt"`
	Permissions []permission `json:"permissions"`
}

type createRequest struct {
	Name             string       `json:"name"`
	Namespace        string       `json:"namespace"`
	TargetNamespaces []string     `json:"targetNamespaces"`
	TTLSeconds       *int64       `json:"ttlSeconds"`
	Permissions      []permission `json:"permissions"`
}

type tokenResponse struct {
	Identity identity `json:"identity"`
	Token    string   `json:"token"`
	Expires  string   `json:"expiresAt"`
}
