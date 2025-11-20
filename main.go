package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	redis "policy-agent/database"
	"policy-agent/k8s"
	"policy-agent/patch"
	"policy-agent/security"
	"policy-agent/types"
	"strings"
	"time"

	"io"
	"log"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request, clients *k8s.Clients) {
	// --- Handle HTTP Methods ---
	switch r.Method {


	// --- GET /auth ---
	case http.MethodGet:
		// --- Generate session data ---
		var session redis.SessionData
		session.ID = security.NewNonce()
		session.Nonce = security.NewNonce()
		session.SecretKey = security.NewSecretKey()
		session.TTL = 5 * time.Minute // 5 minutes

		// --- Save data in redis db ---
		err := redis.SaveSessionData(session)
		if err != nil {
			http.Error(w, "Failed to save session data: "+err.Error(), http.StatusInternalServerError)
			return
		}
		
		// --- Store session.secretKey in Trustee ---
		err = k8s.StoreSessionInTrustee(clients, r.Context(), session)
		if err != nil {
			http.Error(w, "Failed to store session data in trustee: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// FIXME RETURNING SECRET KEY IN RESPONSE FOR TESTING PURPOSES ONLY
		log.Printf("Session stored in trustee: ID=%s, Nonce=%s, SecretKey=%x", session.ID, session.Nonce, session.SecretKey)
		// --- Return session id and nonce to client ---
		w.Header().Set("Content-Type", "application/json")
		// FIXME --- REMOVE SECRET KEY IN RESPONSE AFTER TESTING ---
		json.NewEncoder(w).Encode(map[string]string{"session_id": session.ID, "nonce": session.Nonce, "secret_key": hex.EncodeToString(session.SecretKey)})


	// --- POST /patch ---
	case http.MethodPost:
		var req types.PolicyRequest

		req.Header.Nonce = r.Header.Get("X-Nonce") // e.g. "cce471c3-1d85-4787-8299-f5c222c2a82f"
		req.Header.HashAlgo = r.Header.Get("X-Hash-Algorithm") // e.g. "SHA256"
		req.Header.HashValue = r.Header.Get("X-Hash-Value") // SHA256<req.body> e.g. "abcdef123456..."
		req.Header.HMAC = r.Header.Get("Authorization") // e.g. "HMAC-SHA256 base64signature"

		// --- Parse Body to PolicyRequest type ---
		data, err := io.ReadAll(r.Body) // Read raw request body
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

		// Check supported hash algorithm
		algo := strings.ToUpper(req.Header.HashAlgo)
		if algo != "SHA256" {
			http.Error(w, "unsupported X-Hash-Algorithm", http.StatusBadRequest)
			return
		}

		// --- Validate Body Hash ---
		sum := sha256.Sum256(data)
		hashHex := hex.EncodeToString(sum[:])
		if !strings.EqualFold(hashHex, req.Header.HashValue) {
			http.Error(w, "content hash mismatch", http.StatusUnauthorized)
			return
		}

		// Get Session data from redis for validation
		savedSession, err := redis.GetSessionData(req.Body.SessionID)
		if err != nil {
			http.Error(w, "Failed to retrieve session data: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// --- Validate Redis Session ---
		// Check TTL of Nonce
		if savedSession.TTL <= 0 {
			// Delete session data from Redis
			_ = redis.DeleteSessionData(savedSession.ID)
			http.Error(w, "Session has expired", http.StatusUnauthorized)
			return
		}
		// compare nonce to saved one
		if subtle.ConstantTimeCompare([]byte(req.Header.Nonce), []byte(savedSession.Nonce)) != 1 {
			http.Error(w, "invalid nonce", http.StatusUnauthorized)
			return
		}

		// --- HMAC Verification ---
		err = security.VerifyHMAC(data, req.Header.Nonce, req.Header.HMAC, savedSession.SecretKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		log.Printf("Patch request verified successfully for session %s", req.Body.SessionID)
		
		// --- Run Patch ---
		patch.PatchHandler(clients, w, req)

		// --- Delete session from trustee ---
		err = k8s.DeleteTrusteeSession(clients, savedSession)
		if err != nil {
			log.Printf("Failed to delete session data from trustee: %v", err)
		}
		// --- Nonce/Session consumption (Replay protection) ---
		_ = redis.DeleteSessionData(savedSession.ID)
	
		w.Write([]byte("Patched successfully\n"))

	default:
		http.Error(w, "Only GET or POST allowed", http.StatusMethodNotAllowed)
	}
}

func main() {
	
	// --- Initialize Redis client ---
	if err := redis.InitRedis(); err != nil {
		log.Fatalf("Redis init failed: %v", err)
	}

	// --- Initialize Kubernetes clients ---
	clients, err := k8s.InitClients()
	if err != nil { log.Fatal(err) }

	// --- Ping Kubernetes API servers to verify connectivity ---
	err = k8s.PingAPI(context.Background(), clients)
	if err != nil {
		log.Fatalf("Kubernetes API ping failed: %v", err)
	}
	log.Println("Kubernetes clients initialized successfully.")
	
	// --- Check ServiceAccount existence ---
	err = k8s.CheckServiceAccountExists(clients)
	if err != nil {
		log.Fatalf("ServiceAccount check failed: %v", err)
	}

	// --- Set up the HTTP server with TLS ---
	// Handle GET request to init a session
	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		handler(w, r, clients)
	})
	// Handle POST request to apply a policy update
	http.HandleFunc("/patch",  func(w http.ResponseWriter, r *http.Request) {
		handler(w, r, clients)
	})

	// --- Certification setup ---
	// NOTE: In this setup, we are not using client certificates, but the server could be configured to require them.
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{},
		ClientAuth:   tls.NoClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	cert, err := tls.LoadX509KeyPair("assets/server.crt", "assets/server.key") // server's own public cert + private key
	if err != nil {
		log.Fatal("failed to load server cert/key:", err)
	}
	tlsConfig.Certificates = []tls.Certificate{cert} // configure server to use this cert/key pair

	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
	}

	// --- Start https server ---
	log.Println("Starting HTTPS server on :8443...")
	err = server.ListenAndServeTLS("", "") // cert and key are already configured in tlsConfig
	if err != nil {
		log.Fatal(err)
	}
}
