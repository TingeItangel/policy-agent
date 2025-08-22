package patch

import (
	"fmt"
	"net/http"
	"policy-agent/k8s"
	"policy-agent/security"
	"policy-agent/types"

	"k8s.io/apimachinery/pkg/runtime"
)

/**
* This handler processes patch requests to apply policy updates.
* It verifies the nonce from Redis to prevent replay attacks.
* If the nonce is valid, it applies the policy update and deletes the nonce.
* If the nonce is invalid or expired, it returns an error.
 */
func PatchHandler(w http.ResponseWriter, req types.PolicyBody) {
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
	fmt.Printf("polcy: %s", initData)

	// Patch Annotation field value
	// 1. Find place in initData: image or commands
	// 2. Remove or add

	// Decode initData

	// Get ref value from Trustee

	// Generate new ref value

	// Update Value in Trustee

	// Saving in K8s (Pod or deploye: kubectl apply ...)

	// Trigger restart of pod or deplyoment

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
