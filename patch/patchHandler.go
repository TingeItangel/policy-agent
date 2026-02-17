package patch

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"policy-agent/k8s"
	"policy-agent/security"
	"policy-agent/types"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

/**
* This handler processes patch requests to apply kata-policy updates.
* It retrieves the target deployment from the remote cluster, extracts and decrypts
* the initData annotation, updates the policy.rego according to the request body,
* re-encrypts the initData, and applies the updated annotation back to the deployment.
 */
func PatchHandler(clients *k8s.Clients, w http.ResponseWriter, req types.PolicyRequest) {

	// --- Preparation ---
	// --- Get current mr_config_id from  running deployment ---
	oldMrConfigId, err := k8s.GetMrConfigId(clients, req.Body.DeploymentName, req.Body.Namespace)
	log.Printf("Current config_mr value obtained from remote cluster: %s", oldMrConfigId)
	if err != nil {
		http.Error(w, "Failed to get current mr_config_id from remote cluster: "+err.Error(), http.StatusBadRequest)
		return
	}

	// find Deployment in the remote cluster
	deployment, err := k8s.GetDeploymentFromCluster(clients.Remote, req)
	if err != nil {
		http.Error(w, "Failed to find deployment in remote cluster", http.StatusBadRequest)
		return
	}
	log.Printf("Deployment found in remote cluster: %s/%s", req.Body.Namespace, req.Body.DeploymentName)

	// --- Extract and Decrypt initData ---
	log.Printf("Extracting and decrypting initData annotation for deployment %s/%s", req.Body.Namespace, req.Body.DeploymentName)
	// Get Annotation field value from deployment
	b64InitData, err := k8s.GetInitDataFromAnnotation(deployment)
	if err != nil {
		log.Printf("Error getting initData annotation: %v", err)
		http.Error(w, "Failed to get initData annotation from deployment", http.StatusBadRequest)
		return
	}
	// Decrypt base64 annotation value
	initData, err := security.DecryptBase64(b64InitData)
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
	log.Printf("✅ Extracted policy.rego from initData successfully")

	// --- Start policy update ---
	log.Printf("Starting policy update for deployment %s/%s", req.Body.Namespace, req.Body.DeploymentName)
	updatedRego, err := updatePolicyData(policyRego, req.Body)
	if err != nil {
		http.Error(w, "Failed to update policy data", http.StatusBadRequest)
		return
	}

	// Replace policy.rego with the updated one
	dataSection["policy.rego"] = updatedRego

	newInitDataToml, err := buildInitDataToml(parsed, dataSection)
	if err != nil {
		http.Error(w, "Failed to rebuild initData TOML", http.StatusInternalServerError)
		return
	}

	// Encode base64 and gzip again
	newB64InitData, err := security.EncryptBase64(newInitDataToml)
	if err != nil {
		http.Error(w, "Failed encrypt the new initdata in base64", http.StatusBadRequest)
		return
	}
	log.Printf("✅ Updated and Re-encrypted updated initData successfully")

	// --- Apply patch in remote cluster ---
	log.Printf("Applying updated initData annotation to deployment %s/%s in remote cluster", req.Body.Namespace, req.Body.DeploymentName)
	err = k8s.UpdateAnnotationValue(clients.Remote, deployment, newB64InitData, req.Body.Namespace)
	if err != nil {
		http.Error(w, "Failed to apply patch to remote cluster", http.StatusBadRequest)
		return
	}
	log.Printf("✅ Patch applied successfully to deployment %s/%s in remote cluster", req.Body.Namespace, req.Body.DeploymentName)

	// --- Wait for Deployment rollout ---
	log.Printf("Waiting for deployment %s/%s rollout to complete", req.Body.Namespace, req.Body.DeploymentName)
	err = k8s.WaitForDeploymentRollout(clients.Remote, req.Body.Namespace, req.Body.DeploymentName, 2*time.Minute)
	if err != nil {
		http.Error(w, "Timed out waiting for deployment rollout", http.StatusBadRequest)
		return
	}
	log.Printf("✅ Deployment %s/%s rollout completed successfully", req.Body.Namespace, req.Body.DeploymentName)

	// --- Get new config_mr value from the remote cluster ---
	log.Printf("Getting new config_mr value from remote cluster for deployment %s/%s", req.Body.Namespace, req.Body.DeploymentName)
	newMrConfigId, err := k8s.GetMrConfigId(clients, req.Body.DeploymentName, req.Body.Namespace)
	if err != nil {
		http.Error(w, "Failed to get new config_mr from remote cluster", http.StatusBadRequest)
		return
	}
	// shorten log output for readability and security
	log.Printf("Obtained new config_mr value: %s", newMrConfigId[:12]+"...")

	// --- Patch reference values in trustee ---
	log.Printf("Patching reference values in trustee")
	err = k8s.UpdateReferenceValues(clients, newMrConfigId, oldMrConfigId)
	if err != nil {
		http.Error(w, "Can not patch the reference values in trustee", http.StatusBadRequest)
		return
	}
	log.Printf("✅ Reference values in trustee patched successfully")
	// NOTE: k8s restarts pods automatically: see kubectl describe deployment <name> -n <namespace>
}

// ---------- Internal Functions ----------

/**
* This function updates the policy data in the given Rego policy according to the request body.
* It adds or removes allowed images and commands based on the 'deny' flag in the request.
* It ensures that essential policy blocks are present and that the policy_data block is correctly formatted.
* @param policyRego The original Rego policy as a string.
* @param req The PolicyRequestBody containing images, commands, and the deny flag.
* @return The updated Rego policy as a string, or an error if the update fails.
 */
func updatePolicyData(policyRego string, req types.PolicyRequestBody) (string, error) {
	// --- Check that essential rules exist ---
	requiredBlocks := []string{
		`CreateContainerRequest\s+if\s*{\s*every\s+storage\s+in\s+input\.storages\s*{\s*some\s+allowed_image\s+in\s+policy_data\.allowed_images\s*storage\.source\s*==\s*allowed_image\s*}\s*}`,
		`ExecProcessRequest\s+if\s*{\s*input_command\s*=\s*concat\(" ",\s*input\.process\.Args\)\s*some\s+allowed_command\s+in\s+policy_data\.allowed_commands\s*input_command\s*==\s*allowed_command\s*}`,
	}

	for _, block := range requiredBlocks {
		matched, err := regexp.MatchString(block, policyRego)
		if err != nil {
			return "", fmt.Errorf("regex error: %w", err)
		}
		if !matched {
			return "", fmt.Errorf("required policy block missing: %s", block)
		}
	}
	// --- Check for existing policy_data block ---
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
		// --- policy_data does exist ---
		// Extract JSON-like block
		policyBlock := matches[1]
		policyBlock = cleanPolicyBlock(policyBlock)

		// Parse into map
		if err := json.Unmarshal([]byte(policyBlock), &policyMap); err != nil {
			return "", fmt.Errorf("failed to parse policy_data: %w", err)
		}
	}

	// Ensure keys exist otherwise the policy map is unnecessary
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

/**
* Check if a string slice contains a value
 */
func contains(list []string, val string) bool {
	return slices.Contains(list, val)
}

/**
* Remove a value from a string slice
 */
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

/**
* This function creates a the toml content with the old unchanged and new values
* @return the toml content as string
 */
func buildInitDataToml(parsed map[string]any, dataSection map[string]any) (string, error) {
	// Extract top-level values
	version, _ := parsed["version"].(string)
	algorithm, _ := parsed["algorithm"].(string)

	// dataSection, ok := parsed["data"].(map[string]interface{})
	// if !ok {
	// 	return "", fmt.Errorf("missing [data] section")
	// }

	// Extract in fixed order
	policyRego, _ := dataSection["policy.rego"].(string)
	aaToml, _ := dataSection["aa.toml"].(string)
	cdhToml, _ := dataSection["cdh.toml"].(string)

	// Rebuild string manually
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("version = %q\n", version))
	sb.WriteString(fmt.Sprintf("algorithm = %q\n", algorithm))
	sb.WriteString("[data]\n")

	// Write policy.rego block
	sb.WriteString("\"policy.rego\" = '''\n")
	sb.WriteString(policyRego)
	sb.WriteString("\n'''\n\n")

	// Write aa.toml block
	sb.WriteString("\"aa.toml\" = '''\n")
	sb.WriteString(aaToml)
	sb.WriteString("\n'''\n\n")

	// Write cdh.toml block
	sb.WriteString("\"cdh.toml\" = '''\n")
	sb.WriteString(cdhToml)
	sb.WriteString("\n'''\n")

	return sb.String(), nil
}
