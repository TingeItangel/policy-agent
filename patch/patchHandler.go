package patch

import (
	"fmt"
	"net/http"
	"policy-agent/k8s"
	"policy-agent/security"
	"policy-agent/trustee"
	"policy-agent/types"
	"regexp"
	"slices"
	"strings"

	"encoding/json"

	"github.com/pelletier/go-toml/v2"
)

/**
* This handler processes patch requests to apply policy updates.
* It verifies the nonce from Redis to prevent replay attacks.
* If the nonce is valid, it applies the policy update and deletes the nonce.
* If the nonce is invalid or expired, it returns an error.
 */
func PatchHandler(w http.ResponseWriter, req types.PolicyRequestBody) {

	// --- Preparation ---
	// find deplyoment in the untrusted cluster
	deployment, err := k8s.GetDeploymentFromUntrustedCluster(req)
	if err != nil {
		http.Error(w, "Failed to get deployment object from the untrusted cluster", http.StatusBadRequest)
		return
	}

	// Get Annotaion field value from deployment
	b64InitData, err := k8s.GetInitDataFromAnnotaion(deployment)
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

	// --- Start policy update ---
	updatedRego, err := updatePolicyData(policyRego, req)
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

	// --- Patch ref values in trustee ---
	err = trustee.PatchReferenceValues()
	if err != nil {
		http.Error(w, "Can not patch the reference values in trustee", http.StatusBadRequest)
		return
	}

	// --- Apply patch in local cluster ---
	err = k8s.UpdateAnnotationValue(deployment, newB64InitData, req.Namespace)
	if err != nil {
		http.Error(w, "Failed to apply patch to k8s cluster", http.StatusBadRequest)
		return
	}
	// NOTE: k8s restarts pods automaticly: see kubectl describe deployment <name> -n <namespace>
}

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

/**
* This function creates a the toml content with the old unchanged and new values
* @return the toml content as string
 */
func buildInitDataToml(parsed map[string]interface{}, newDataSection map[string]interface{}) (string, error) {
	// Extract top-level values
	version, _ := parsed["version"].(string)
	algorithm, _ := parsed["algorithm"].(string)

	dataSection, ok := parsed["data"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("missing [data] section")
	}

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
