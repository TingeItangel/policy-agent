package patch

import (
	"fmt"
	"net/http"
	"policy-agent/k8s"
	"policy-agent/security"
	"policy-agent/types"
	"regexp"
	"slices"

	"encoding/json"

	"github.com/pelletier/go-toml/v2"
	"k8s.io/apimachinery/pkg/runtime"
)

/**
* This handler processes patch requests to apply policy updates.
* It verifies the nonce from Redis to prevent replay attacks.
* If the nonce is valid, it applies the policy update and deletes the nonce.
* If the nonce is invalid or expired, it returns an error.
 */
func PatchHandler(w http.ResponseWriter, req types.PolicyBody) {
	// --- preparation ---
	// find pod or deplyoment in k8s cluster
	runtimeObj, err := findPatchTarget(req)
	if err != nil {
		http.Error(w, "Finding Target in K8s Cluster faild", http.StatusBadRequest)
		return
	}

	// Get Annotaion field value
	base64InitData, err := k8s.GetInitDataFromAnnotaion(runtimeObj, req.IsDeployment)
	// Decrypt base64
	initData, err := security.DecryptBase64(base64InitData)
	if err != nil {
		http.Error(w, "Policy Data can not be read", http.StatusBadRequest)
		return
	}

	// Parse TOML into a generic map
	var parsed map[string]interface{}
	if err := toml.Unmarshal([]byte(initData), &parsed); err != nil {
		http.Error(w, "Failed to parse initData as TOML", http.StatusBadRequest)
		return
	}

	// Extract [data] section
	dataSection, ok := parsed["data"].(map[string]interface{})
	if !ok {
		http.Error(w, "initData missing [data] section", http.StatusBadRequest)
		return
	}
	// Extract "policy.rego" from [data] section
	policyRego, ok := dataSection["policy.rego"].(string)
	if !ok {
		http.Error(w, "initData missing policy.rego", http.StatusBadRequest)
		return
	}

	// -- policy update --
	updatedRego, err := updatePolicyData(policyRego, req)
	if err != nil {
		http.Error(w, "Failed to update policy data", http.StatusBadRequest)
		return
	}
	fmt.Printf("new Rego: %v", updatedRego)

	// -- add new rego in pod or deplyoment object ---

	// --- trustee ---
	// Get ref value from Trustee

	// Generate new ref value

	// Update Value in Trustee

	// --- apply patch in cluster ---
	// apply patch in k8s cluster
	// pod: delete pod and apply new pod witch pod obj from above
	// deployment: patch deployment file and trigger rollout

	// return success

}

func findPatchTarget(req types.PolicyBody) (runtime.Object, error) {
	if req.Target == "" {
		return nil, fmt.Errorf("target must not be empty")
	}

	// NOTE: Target is a Deployment
	if req.IsDeployment {
		deployment, err := k8s.GetDeplyoment(req.Namespace, req.Target)
		if err != nil {
			return nil, fmt.Errorf("failed to get deployment %s/%s: %w", req.Namespace, req.Target, err)
		}
		return deployment, nil
	}

	// NOTE: Target is a Pod
	pod, err := k8s.GetPod(req.Namespace, req.Target)
	if err != nil {
		return nil, fmt.Errorf("failed to get pod %s/%s: %w", req.Namespace, req.Target, err)
	}
	return pod, nil
}

/**
*
 */
func updatePolicyData(policyRego string, req types.PolicyBody) (string, error) {
	re := regexp.MustCompile(`(?s)policy_data\s*:=\s*({.*?})`)
	matches := re.FindStringSubmatch(policyRego)

	var policyMap map[string][]string

	if len(matches) < 2 {
		// --- policy_data does not exist ---
		if req.Deny {
			// nothing to remove: return unchanged
			return policyRego, nil
		}

		// Create a fresh map
		policyMap = map[string][]string{
			"allowed_commands": {},
			"allowed_images":   {},
		}
	} else {
		// --- Extract JSON-like block ---
		policyBlock := matches[1]
		policyBlock = cleanPolicyBlock(policyBlock)

		// Parse into map
		if err := json.Unmarshal([]byte(policyBlock), &policyMap); err != nil {
			return "", fmt.Errorf("failed to parse policy_data: %w", err)
		}
	}

	// Ensure keys exist
	if _, ok := policyMap["allowed_commands"]; !ok {
		policyMap["allowed_commands"] = []string{}
	}
	if _, ok := policyMap["allowed_images"]; !ok {
		policyMap["allowed_images"] = []string{}
	}

	// --- Modify according to request body ---
	if req.Deny {
		// Remove requested commands/images
		for _, img := range req.Images {
			policyMap["allowed_images"] = remove(policyMap["allowed_images"], img)
		}
		for _, cmd := range req.Commands {
			policyMap["allowed_commands"] = remove(policyMap["allowed_commands"], cmd)
		}
	} else {
		// Add requested commands/images (if not already present)
		for _, img := range req.Images {
			if !contains(policyMap["allowed_images"], img) {
				policyMap["allowed_images"] = append(policyMap["allowed_images"], img)
			}
		}
		for _, cmd := range req.Commands {
			if !contains(policyMap["allowed_commands"], cmd) {
				policyMap["allowed_commands"] = append(policyMap["allowed_commands"], cmd)
			}
		}
	}

	// Serialize back
	updatedJSON, err := json.MarshalIndent(policyMap, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to serialize updated policy_data: %w", err)
	}

	if len(matches) < 2 {
		// Inject a fresh block at the end of the policy rego
		updatedRego := policyRego + "\n\npolicy_data := " + string(updatedJSON)
		return updatedRego, nil
	}

	// Replace old block
	updatedRego := re.ReplaceAllString(policyRego, fmt.Sprintf("policy_data := %s", updatedJSON))
	return updatedRego, nil
}

func contains(list []string, val string) bool {
	return slices.Contains(list, val)
}

func remove(list []string, val string) []string {
	result := []string{}
	for _, v := range list {
		if v != val {
			result = append(result, v)
		}
	}
	return result
}

/**
*  Remove trailing commas before ] or }
 */
func cleanPolicyBlock(block string) string {
	block = regexp.MustCompile(`,(\s*])`).ReplaceAllString(block, "$1")
	block = regexp.MustCompile(`,(\s*})`).ReplaceAllString(block, "$1")
	return block
}
