package main

import (
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	adminToken := os.Getenv("ADMIN_API_TOKEN")
	if len(adminToken) < 32 {
		log.Fatal("ADMIN_API_TOKEN must contain at least 32 characters")
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

	app := newAPI(client, adminToken, namespaces)
	server := &http.Server{
		Addr:              envOr("LISTEN_ADDR", "127.0.0.1:8080"),
		Handler:           app.routes(),
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
