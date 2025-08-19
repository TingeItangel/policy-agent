package security

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"policy-agent/policy-agent/types"
	"strings"
)

func RequestBodyValidation(req types.PolicyRequest) bool {
	// NOTE: Check Nonce
	if req.Body.Nonce == "" {
		return false
	}

	// NOTE: compare nonce
	valid, errMsg := isValidNonce(req.Body.Nonce)
	if !valid {
		if errMsg != "" {
			// TODO: add Logs in read only file here
			fmt.Printf("Nonce validation failed: %v", errMsg)
		}
		return false
	}

	// NOTE: Delete the nonce after successful verification to prevent replay attacks and race conditions
	// err := deleteNonce(req.Body.Nonce)
	// if err != nil {
	// 	return false
	// }

	// NOTE: Check Target
	if req.Body.Target == "" {
		return false
	}

	// NOTE: Check Namespace (no namespace == "default")
	// TODO: if target does not exist in namespace, return false
	// TODO: Make K8s API call to check if target exists

	// BUG removed to test hashing first
	// pod, err := k8s.GetPod(req.Target, req.Namespace)
	// log.Printf("%v", pod)

	// NOTE: Is Annotation empty?
	//TODO: is annotaion field always the same name? If yes: can be removed here
	// NOTE: Ether Commands or Image must be set
	// NOTE: Is Deny set? Deafult is ture, to ensure that the policy is not applied by default
	// TODO:

	return true
}

/**
* Compare HashValue of Request Body and own calculation
* returns true if hashes are same, false if not
 */
func CompareHash(body []byte, hashAlgo string, hashValue string) bool {
	// Calculate own hash over body
	calculatedHash, err := calculateHash(body, hashAlgo)
	if err != nil {
		return false
	}
	// Compare calculated hash with the received one
	if !strings.EqualFold(calculatedHash, hashValue) {
		return false
	}
	return true
}

/**
* Calculate Hash of provided data
* return hash string
 */
func calculateHash(data []byte, hashAlgo string) (string, error) {
	var h hash.Hash

	switch strings.ToLower(hashAlgo) {
	case "sha256":
		h = sha256.New()
	case "sha512":
		h = sha512.New()
	case "sha1":
		h = sha1.New()
	case "md5":
		h = md5.New()
	default:
		return "", fmt.Errorf("unsupported hash type: %s", hashAlgo)
	}

	h.Write(data)
	return hex.EncodeToString(h.Sum(nil)), nil
}
