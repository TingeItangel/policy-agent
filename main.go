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
	// Early return if the request method is not GET or POST
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "Only GET or POST allowed", http.StatusMethodNotAllowed)
		return
	}

	// --- Handle GET requests ---
	if r.Method == http.MethodGet {
		success, nonce := security.GetNewNonce()
		// Return nonce to the client
		if !success {
			http.Error(w, "Failed to get nonce", http.StatusBadRequest)
			return

		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"nonce": nonce})
		return
	}

	// --- Handle POST request to apply a policy update ---
	var req types.PolicyRequest

	req.Header.HashAlgo = r.Header.Get("X-Hash-Algorithm")
	req.Header.HashValue = r.Header.Get("X-Hash-Value")

	// --- Parse Body to PolicyRequest type ---
	// 1. Read raw request body
	data, err := io.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	// 2. Unmarshal into your typed struct
	if err := json.Unmarshal(data, &req.Body); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// TODO: replace with signiture check or use both!
	// FIXME: Hash has difference. Why is this?
	// 3. Canonicalize the body by re-marshalling
	// canonicalJSON, err := canonicaljson.Marshal(req.Body)
	// if err != nil {
	// 	http.Error(w, "Failed to marshal canonical JSON", http.StatusInternalServerError)
	// 	return
	// }

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

	// NOTE: --- Run Patch ---
	patch.PatchHandler(w, req.Body)

	log.Printf("Target: %s, Namespace: %s, Value: %s", req.Body.DeplyomentName, req.Body.Namespace, req.Body.Images)
	// log.Printf("Commands: %v, IsDeployment: %t, Deny: %t", req.Commands, req.IsDeployment, req.Deny)

	// log.Printf("Running command: %v", cmd.String())
	// log.Printf("Command output: %s", string(output))

	w.Write([]byte("Patched successfully\n"))
}

func main() {
	// Initialize Redis client
	if err := redis.InitRedis("localhost:6379", "", 0); err != nil {
		log.Fatalf("Redis init failed: %v", err)
	}
	// Initialize Kubernetes client
	if err := k8s.Init(); err != nil {
		log.Fatalf("K8s init faild: %v", err)
	}

	// TODO: Get needed Keys from Trustee
	// TODO: Load Key of TEE to check signiture

	// NOTE: Set up the HTTP server with TLS
	// Handle GET request to generate a nonce and return it to the client
	http.HandleFunc("/nonce", handler)
	// Handle POST request to apply a policy update
	http.HandleFunc("/patch", handler)

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

	log.Println("Starting HTTPS server on :8443...")
	err = server.ListenAndServeTLS("cert.pem", "key.pem")
	if err != nil {
		log.Fatal(err)
	}
	// BUG:Can the server crash? If yes the pod should be restartet. Is that possible to do?
}
