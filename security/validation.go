package security

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"
	"unicode"
)

/**
* checks that HMAC(sha256(body) + "." + nonce, secretKey) == givenHMAC
* payloadHash = SHA256(body)
* message = payloadHash + "." + nonce
* expectedHMAC = Base64Encode( HMAC-SHA256(message, secretKey) )
 */
func VerifyHMAC(body []byte, nonce string, givenHMAC string, secretKey []byte) error {
	if len(secretKey) == 0 {
		return fmt.Errorf("empty secret key")
	}
	if nonce == "" {
		return fmt.Errorf("empty nonce")
	}
	givenHMAC = strings.TrimSpace(givenHMAC)

	// Remove scheme prefix if present
	const scheme = "HMAC-SHA256 "
	if strings.HasPrefix(strings.ToUpper(givenHMAC), strings.ToUpper(scheme)) {
		givenHMAC = strings.TrimSpace(givenHMAC[len(scheme):])
	}

	// Base64-signature decode
	givenSig, err := base64.StdEncoding.DecodeString(givenHMAC)
	if err != nil {
		return fmt.Errorf("bad signature encoding: %w", err)
	}

	// Normalize secret key
	keyRaw, err := normalizeKey(secretKey)
	if err != nil {
		return fmt.Errorf("normalize key: %w", err)
	}

	sum := sha256.Sum256(body)
	hashHex := hex.EncodeToString(sum[:])

	msg := hashHex + "." + nonce

	// calculate HMAC
	mac := hmac.New(sha256.New, keyRaw)
	mac.Write([]byte(msg))
	expected := mac.Sum(nil)

	if !hmac.Equal(givenSig, expected) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

/**
* Compare HashValue of Request Body and own calculation
* returns true if hashes are same, false if not
 */
// func CompareHash(data []byte, hashAlgo string, hashValue string) bool {
// 	// Calculate own hash over body
// 	calculatedHash, err := calculateHash(data, hashAlgo)
// 	if err != nil {
// 		return false
// 	}
// 	// Compare calculated hash with the received one
// 	if !strings.EqualFold(calculatedHash, hashValue) {
// 		return false
// 	}
// 	return true
// }

// ---------- Internal Functions ----------

/**
* Normalize secret key from various formats to raw byte slice
 */
func normalizeKey(secretKey []byte) ([]byte, error) {
	s := strings.TrimSpace(string(secretKey))

	// Try Hex first
	isHex := len(s)%2 == 0
	if isHex {
		for _, r := range s {
			if !unicode.IsDigit(r) && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
				isHex = false
				break
			}
		}
	}
	if isHex && len(s) >= 64 { // 64 Hex-Characters = 32 Bytes
		if b, err := hex.DecodeString(s); err == nil {
			return b, nil
		}
	}

	// Try Base64 (if someone encoded the key in b64)
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) > 0 {
		return b, nil
	}

	// Otherwise use as delivered (raw)
	return secretKey, nil
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
