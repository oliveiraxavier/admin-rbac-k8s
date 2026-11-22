package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"admin-rbac-k8s/internal/api"
	"admin-rbac-k8s/internal/authentik"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	authConfig := authentik.Config{
		IssuerURL:     os.Getenv("AUTHENTIK_ISSUER_URL"),
		ClientID:      os.Getenv("AUTHENTIK_CLIENT_ID"),
		ClientSecret:  os.Getenv("AUTHENTIK_CLIENT_SECRET"),
		RedirectURL:   os.Getenv("AUTHENTIK_REDIRECT_URL"),
		SessionSecret: os.Getenv("AUTHENTIK_SESSION_SECRET"),
		AllowedGroups: splitList(os.Getenv("AUTHENTIK_ALLOWED_GROUPS")),
	}
	authenticator, err := authentik.New(context.Background(), authConfig)
	if err != nil {
		log.Fatalf("configure Authentik login: %v", err)
	}

	namespaces := splitList(os.Getenv("TARGET_NAMESPACES"))
	if len(namespaces) == 0 {
		log.Fatal("TARGET_NAMESPACES must list at least one namespace")
	}

	config, err := kubeConfig()
	if err != nil {
		log.Fatalf("load Kubernetes config: %v", err)
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("create Kubernetes client: %v", err)
	}

	server := &http.Server{
		Addr:              envOr("LISTEN_ADDR", "127.0.0.1:8080"),
		Handler:           api.NewHandler(client, namespaces, authenticator),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("Kubernetes access manager listening on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}

func kubeConfig() (*rest.Config, error) {
	if path := os.Getenv("KUBECONFIG"); path != "" {
		return clientcmd.BuildConfigFromFlags("", path)
	}
	config, err := rest.InClusterConfig()
	if err == nil {
		return config, nil
	}
	if errors.Is(err, rest.ErrNotInCluster) {
		return clientcmd.BuildConfigFromFlags("", clientcmd.RecommendedHomeFile)
	}
	return nil, err
}

func splitList(value string) []string {
	var values []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			values = append(values, item)
		}
	}
	return values
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
