package patch

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"policy-agent/policy-agent/types"

	"github.com/redis/go-redis/v9"
)

/**
* This handler processes patch requests to apply policy updates.
* It verifies the nonce from Redis to prevent replay attacks.
* If the nonce is valid, it applies the policy update and deletes the nonce.
* If the nonce is invalid or expired, it returns an error.
 */
func patchHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	body, _ := io.ReadAll(r.Body)
	defer r.Body.Close()

	var req types.PolicyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Verify nonce exists in Redis
	val, err := rdb.Get(ctx, req.Nonce).Result()
	if err == redis.Nil || val != "valid" {
		http.Error(w, "Invalid or expired nonce", http.StatusForbidden)
		return
	}
	if err != nil {
		http.Error(w, "Redis error", http.StatusInternalServerError)
		return
	}

	// Delete nonce from Redis after use to prevent replay
	rdb.Del(ctx, req.Nonce)

	// Log request details (instead of executing kubectl in this example)
	log.Printf("Incoming patch request: %+v", req)

	// Example: Load policy from annotation
	policy, err := loadPolicyFromAnnotation(req.Annotation)
	if err != nil {
		http.Error(w, "Failed to load policy from annotation", http.StatusInternalServerError)
		return
	}

	log.Printf("Policy loaded: %v", policy)

	w.Write([]byte("Patched successfully with nonce verification\n"))
}

// loadPolicyFromAnnotation is a stub for retrieving policies
func loadPolicyFromAnnotation(annotation string) (map[string]string, error) {
	return map[string]string{"policy": "dummy-policy"}, nil
}

func findPatchTarget(req types.PolicyRequest) (string, error) {
	// This function would contain logic to find the target for the patch
	// For now, we return a dummy target
	if req.Target == "" {
		return "", nil
	}
	return "dummy-target", nil

}
