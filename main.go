package main

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"os"
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
		session.TTL = 2 * time.Minute // 2 minutes
		session.Used = false

		// --- Save data in redis db ---
		err := redis.SaveSessionData(session)
		if err != nil {
			http.Error(w, "Failed to save session data: "+err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("✅ Storing session in Redis successfully: ID=%s", session.ID[:8])
		
		// --- Store session.secretKey in Trustee ---
		err = k8s.StoreSessionInTrustee(clients, r.Context(), session)
		if err != nil {
			http.Error(w, "Failed to store session data in trustee: "+err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("✅ Session stored in trustee successfully: ID=%s, Nonce=%s", session.ID, session.Nonce)

		// --- Return session id and nonce to client ---
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"session_id": session.ID, "nonce": session.Nonce})

	// --- POST /patch ---
	case http.MethodPost:
		var req types.PolicyRequest

		req.Header.Nonce = r.Header.Get("X-Nonce")             // e.g. "cce471c3-1d85-4787-8299-f5c222c2a82f"
		req.Header.HashAlgo = r.Header.Get("X-Hash-Algorithm") // e.g. "SHA256"
		req.Header.HashValue = r.Header.Get("X-Hash-Value")    // SHA256<req.body> e.g. "abcdef123456..."
		req.Header.HMAC = r.Header.Get("Authorization")        // e.g. "HMAC-SHA256 base64signature"

		// --- Parse Body to PolicyRequest type ---
		data, err := io.ReadAll(r.Body) // Read raw request body
		defer r.Body.Close()
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}
		// save into own typed struct
		if err := json.Unmarshal(data, &req.Body); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// --- Check supported hash algorithm ---
		algo := strings.ToUpper(req.Header.HashAlgo)
		if algo != "SHA256" && algo != "SHA-512" {
			http.Error(w, "unsupported X-Hash-Algorithm", http.StatusBadRequest)
			return
		}

		// --- Validate Body Hash ---
		var sum []byte
		switch algo {
		case "SHA256":
			h := sha256.Sum256(data)
			sum = h[:]
		case "SHA-512":
			h := sha512.Sum512(data)
			sum = h[:]
		}
		hashHex := hex.EncodeToString(sum)
		if !strings.EqualFold(hashHex, req.Header.HashValue) {
			http.Error(w, "content hash mismatch", http.StatusUnauthorized)
			return
		}
		log.Printf("✅ Request body hash verified successfully for session %s", req.Body.SessionID)

		// --- Retrieve Session Data from Redis ---
		savedSession, err := redis.GetSessionData(req.Body.SessionID)
		if err != nil {
			http.Error(w, "Failed to retrieve session data: "+err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("✅ Session data retrieved from Redis successfully: ID=%s", savedSession.ID)

		// --- Validate Redis Session ---
		// Check if session is used
		used, err := redis.IsSessionUsed(savedSession.ID)
		if err != nil {
			http.Error(w, "Failed to check session usage in DB: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if used {
			http.Error(w, "Session already used", http.StatusUnauthorized)
			return
		}
		// Mark session as used
		err = redis.MarkSessionAsUsed(savedSession.ID)
		if err != nil {
			http.Error(w, "Failed to mark session as used in DB: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// Check TTL
		if savedSession.TTL <= 0 { // Check TTL of Nonce
			// Delete session data from Redis
			//_ = redis.DeleteSessionData(savedSession.ID)
			http.Error(w, "Session has expired", http.StatusUnauthorized)
			return
		}
		log.Printf("✅ Session verified successfully for session %s", savedSession.ID)

		// --- Nonce Verification ---
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

		log.Printf("✅ Patch request verified successfully for session %s", req.Body.SessionID)

		// --- Run Patch ---
		log.Printf("Applying patch to deployment %s in namespace %s", req.Body.DeploymentName, req.Body.Namespace)
		patch.PatchHandler(clients, w, req)
		log.Printf("✅ Patch applied successfully to deployment %s in namespace %s", req.Body.DeploymentName, req.Body.Namespace)

		// --- Delete session from trustee ---
		err = k8s.DeleteTrusteeSession(clients, savedSession)
		if err != nil {
			log.Printf("Failed to delete session data from trustee: %v", err)
		}
		log.Printf("✅ Session data deleted from trustee successfully: ID=%s", savedSession.ID)
		// --- Nonce/Session consumption (Replay protection) ---
		_ = redis.DeleteSessionData(savedSession.ID)
		log.Printf("✅ Session data deleted from Redis successfully: ID=%s", savedSession.ID)

		// --- Return success ---
		log.Println("✅Patch applied successfully")
		w.Write([]byte("✅ Patched successfully\n"))

	default:
		log.Printf("Unsupported HTTP method: %s", r.Method)
		http.Error(w, "Only GET or POST allowed", http.StatusMethodNotAllowed)
	}
}

// Cleanup Routine
func cleanupRoutine(clients *k8s.Clients) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		<-ticker.C
		// Load all sessionIDs from redis (expired are automatically deleted by redis)
		sessionIDs, err := redis.GetAllSessionIDs()
		// If secret with pa-sessions not found, the error can be ignored and the cleanup can continue, because it means that there are no sessions stored in the trustee and thus no sessions to clean up.
		if os.IsNotExist(err) {
			log.Printf("No sessions found in trustee for cleanup")
			continue
		}
		if err != nil {
			log.Printf("Cleanup-Error: loading session IDs from Redis: %v", err)
			continue
		}
		err = k8s.DeleteExpiredSessions(clients, sessionIDs)
		if err != nil {
			log.Printf("Cleanup-Error: deleting expired sessions from trustee: %v", err)
		}
	}
}

func main() {

	// --- Initialize Redis client ---
	log.Println("Initializing Redis client...")
	if err := redis.InitRedis(); err != nil {
		log.Fatalf("Redis init failed: %v", err)
	}
	log.Println("✅ Redis client initialized successfully.")

	// --- Initialize Kubernetes clients ---
	log.Println("Initializing Kubernetes clients...")
	clients, err := k8s.InitClients()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("✅ Kubernetes clients initialized successfully.")

	// --- Ping Kubernetes API servers to verify connectivity ---
	err = k8s.PingAPI(context.Background(), clients)
	if err != nil {
		log.Fatalf("Kubernetes API ping failed: %v", err)
	}
	log.Println("✅ Kubernetes API ping successful.")

	// --- Check ServiceAccount existence ---
	err = k8s.CheckServiceAccountExists(clients)
	if err != nil {
		log.Fatalf("ServiceAccount check failed: %v", err)
	}
	log.Println("✅ ServiceAccount check successful.")

	// --- Set up the HTTP server with TLS ---
	// Handle GET request to init a session
	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		handler(w, r, clients)
	})
	// Handle POST request to apply a policy update
	http.HandleFunc("/patch", func(w http.ResponseWriter, r *http.Request) {
		handler(w, r, clients)
	})

	// --- Certification setup ---
	// NOTE: In this setup, we are not using client certificates, but the server could be configured to require them.
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{},
		ClientAuth:   tls.NoClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	// Load server certificate and key
	certPath := os.Getenv("POLICY_AGENT_TLS_CERT")
	keyPath := os.Getenv("POLICY_AGENT_TLS_KEY")

	if certPath == "" || keyPath == "" {
		log.Fatal("Cannot start server: POLICY_AGENT_TLS_CERT or POLICY_AGENT_TLS_KEY environment variable not set. Check if the TLS secret is created and mounted correctly.")
	}

	certificate, err := tls.LoadX509KeyPair(certPath, keyPath) // server's own public cert + private key
	if err != nil {
		log.Fatal("failed to load server cert/key:", err)
	}
	tlsConfig.Certificates = []tls.Certificate{certificate} // configure server to use this cert/key pair

	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
	}

	// --- Start cleanup routine ---
	log.Println("Starting cleanup routine...")
	go cleanupRoutine(clients)

	// --- Start https server ---
	log.Println("Starting HTTPS server on :8443...")
	err = server.ListenAndServeTLS("", "") // cert and key are already configured in tlsConfig
	if err != nil {
		log.Fatal(err)
	}
}
