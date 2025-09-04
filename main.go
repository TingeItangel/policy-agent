package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"os"
	redis "policy-agent/database"
	"policy-agent/k8s"
	"policy-agent/patch"
	"policy-agent/security"
	"policy-agent/types"

	"io"
	"log"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {

	case http.MethodGet:
		// --- GET /nonce ---
		success, nonce := security.GetNewNonce()
		if !success {
			http.Error(w, "Failed to get nonce", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"nonce": nonce})

	case http.MethodPost:
		// --- POST /patch ---
		var req types.PolicyRequest

		req.Header.HashAlgo = r.Header.Get("X-Hash-Algorithm")
		req.Header.HashValue = r.Header.Get("X-Hash-Value")

		// --- Parse Body to PolicyRequest type ---
		// Read raw request body
		data, err := io.ReadAll(r.Body)
		defer r.Body.Close()
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}
		// save into your typed struct
		if err := json.Unmarshal(data, &req.Body); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// TODO: replace with signiture check or use both!
		// FIXME: Hash has difference. Why is this?
		// Validate Nonce
		// if !security.ValidateNonce(req.Body.Nonce) {
		// 	http.Error(w, "Invalid or reused nonce", http.StatusUnauthorized)
		// 	return
		// }

		// Validate Hash

		// validHash := security.CompareHash(canonicalJSON, req.Header.HashAlgo, req.Header.HashValue)
		// if !validHash {
		// 	http.Error(w, "Invalid Hash", http.StatusBadRequest)
		// 	return
		// }

		// HACK Skiped for developing. Has to be added again !!!
		// NOTE: --- Validate request body fields ---
		// valid := security.RequestBodyValidation(req)
		// if !valid {
		// 	http.Error(w, "Invalid request body", http.StatusBadRequest)
		// 	return
		// }

		// --- Run Patch ---
		patch.PatchHandler(w, req.Body)

		log.Printf("Patched deployment %s/%s with images: %v",
			req.Body.Namespace, req.Body.DeploymentName, req.Body.Images)

		w.Write([]byte("Patched successfully\n"))

	default:
		http.Error(w, "Only GET or POST allowed", http.StatusMethodNotAllowed)
	}
}

func main() {
	// --- Init --
	// Initialize Redis client
	if err := redis.InitRedis("localhost:6379", "", 0); err != nil {
		log.Fatalf("Redis init failed: %v", err)
	}
	// BUG: REPLACE REDIS WHEN TESTING IN CLUSTER
	// if err := redis.InitRedis("redis:6379", "", 0); err != nil {
	// 	log.Fatalf("Redis init failed: %v", err)
	// }
	// Initialize Kubernetes client
	if err := k8s.InitTrusted(); err != nil {
		log.Fatalf("trusted cluster init failed: %v", err)
	}
	// Untrusted cluster (via mounted SA token + CA)
	// TODO get url from deployment env variable
	apiServerURL := "https://192.168.178.37:6443" // from kubectl cluster-info

	if err := k8s.InitUntrusted(apiServerURL); err != nil {
		log.Fatalf("Failed to init untrusted cluster: %v", err)
	}

	// TODO: Get needed Keys from Trustee
	// TODO: Load Key of TEE to check signiture

	// --- Set up the HTTP server with TLS ---
	// Handle GET request to generate a nonce and return it to the client
	http.HandleFunc("/nonce", handler)
	// Handle POST request to apply a policy update
	http.HandleFunc("/patch", handler)

	// --- Certification setup ---
	// Load the CA certificate
	// TODO Should the certificate be loaded from trustee or from a file?
	// For now, we load it from a file.
	caCert, err := os.ReadFile("ca.crt")
	if err != nil {
		log.Fatal("could not read ca cert:", err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
		MinVersion:   tls.VersionTLS12,
	}

	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatal("failed to load server cert/key:", err)
	}
	tlsConfig.Certificates = []tls.Certificate{cert}

	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
	}

	// --- Start https server ---
	log.Println("Starting HTTPS server on :8443...")
	err = server.ListenAndServeTLS("cert.pem", "key.pem")
	if err != nil {
		log.Fatal(err)
	}
	// BUG:Can the server crash? If yes the pod should be restartet. Is that possible to do?
}
