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

	// NOTE: Handle GET requests
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

	// NOTE: Handle POST request to apply a policy update

	// NOTE: Create PolicyRequest Object
	var req types.PolicyRequest

	req.Header.HashAlgo = r.Header.Get("X-Hash-Algorithm")
	req.Header.HashValue = r.Header.Get("X-Hash-Value")

	// NOTE: Parse Body to PolicyRequest type
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

	// HACK Skiped for developing
	// NOTE: Validate request body fields
	// valid := security.RequestBodyValidation(req)
	// if !valid {
	// 	http.Error(w, "Invalid request body", http.StatusBadRequest)
	// 	return
	// }

	// NOTE: Run Patch
	patch.PatchHandler(w, req.Body)

	/**
	* generate and execute the kubectl patch command
	* Example:
	* Request body:
	* {
	*   "target": "my-deployment",
	*   "namespace": "default",
	*   "annotation": "my-annotation",
	*   "image": "nginx:latest",
	*   "commands": ["echo 'hello'"],
	*   "isDeployment": true,
	*   "deny": false
	* }
	* The command will patch the deployment with the specified annotation and image.
	* --type=merge is used to merge the new annotation into the existing ones.
	* kubectl patch deployment my-deployment -n default --type=merge -p '{"spec":{"template":{"metadata":{"annotations":{"my-annotation":"nginx:latest"}}}}}'
	 */
	// patch := fmt.Sprintf(`{"spec":{"template":{"metadata":{"annotations":{"%s":"%s"}}}}}`, req.Annotation, req.Image)
	// cmd := exec.Command("kubectl", "patch", "deployment", req.Target,
	// 	"-n", req.Namespace,
	// 	"--type=merge",
	// 	"-p", patch)

	/**
	* After the patch a rollout is triggert if isDeployment is true.
	* Otherwise the Pod is restarted. (kubectl delete pod <pod-name> -n <namespace> && kubectl apply -f <deployment-file>)
	* What if not Pod File is provided? => Safe content of Pod File and use it to restart the Pod.
	 */

	/**
	*
	 */

	// output, err := cmd.CombinedOutput()
	// if err != nil {
	// 	http.Error(w, fmt.Sprintf("Patch failed: %s\n%s", err, output), 500)
	// 	return
	// }

	log.Printf("Target: %s, Namespace: %s, Annotation: %s, Value: %s", req.Body.Target, req.Body.Namespace, req.Body.Annotation, req.Body.Image)
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

// loadPolicyFromAnnotation is a stub for retrieving policies
func loadPolicyFromAnnotation(annotation string) (map[string]string, error) {
	return map[string]string{"policy": "dummy-policy"}, nil
}
