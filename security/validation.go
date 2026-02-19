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
	"log"
	"strings"
	"unicode"
)

/**
* checks that HMAC(sha256(body) + "." + nonce, secretKey) == givenHMAC
* hashHex is the own calculated hash of the body (e.g. SHA256(body)) in hex string format
* message = hashHex + "." + nonce
* expectedHMAC = Base64Encode( HMAC-SHA256(message, secretKey) )
 */
func VerifyHMAC(hashHex string, nonce string, givenHMAC string, secretKey []byte, algo string) error {
	if len(secretKey) == 0 {
		return fmt.Errorf("empty secret key")
	}
	if nonce == "" {
		return fmt.Errorf("empty nonce")
	}
	trimmedGivenHMAC := strings.TrimSpace(givenHMAC)

	// Remove scheme prefix if present: shame "HMAC-SHA256 " or "HMAC-SHA512"
	scheme := []string{"HMAC-SHA256 ", "HMAC-SHA512"}
	for _, s := range scheme {
		if strings.HasPrefix(strings.ToUpper(trimmedGivenHMAC), strings.ToUpper(s)) {
			trimmedGivenHMAC = strings.TrimSpace(trimmedGivenHMAC[len(s):])
			break
		}
	}

	// Base64-signature decode
	givenSig, err := base64.StdEncoding.DecodeString(trimmedGivenHMAC)
	if err != nil {
		return fmt.Errorf("bad signature encoding: %w", err)
	}

	msg := hashHex + "." + nonce

	// calculate HMAC
	var mac hash.Hash
	switch strings.ToUpper(algo) {
	case "SHA256":
		mac = hmac.New(sha256.New, secretKey)
	case "SHA512":
		mac = hmac.New(sha512.New, secretKey)
	default:
		return fmt.Errorf("unsupported HMAC algorithm: %s", algo)
	}
	mac.Write([]byte(msg))
	expected := mac.Sum(nil)

	if !hmac.Equal(givenSig, expected) {
		// Log Bytes for Debugging
		log.Printf("givenHMAC before normalization: '%s'", givenHMAC)
		log.Printf("givenHMAC after trimming: '%s'", trimmedGivenHMAC)
		log.Printf("Secret Key (hex): %s", hex.EncodeToString(secretKey))
		log.Printf("Message: %s", msg)
		log.Printf("Expected HMAC (hex): %s", hex.EncodeToString(expected))
		log.Printf("Given HMAC (hex): %s", hex.EncodeToString(givenSig))

		return fmt.Errorf("invalid signature")
	}
	return nil
}


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
