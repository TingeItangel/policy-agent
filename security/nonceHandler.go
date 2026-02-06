package security

import (
	"crypto/rand"
	// "fmt"
	"io"
	// redis "policy-agent/database"

	"github.com/google/uuid"
)

// ---------- nonce ----------
/**
 * This handler generates a unique nonce for the client to use in subsequent requests.
 * The client can retrieve this nonce and include it in their requests to ensure they are valid.
 * Can be used as session identifier as well.
 */
func NewNonce() string {
	nonce := uuid.New().String()
	return nonce
}

/**
 * This function checks if the provided nonce is valid.
 * It retrieves the nonce from Redis and checks its TTL.
 * If the nonce exists and is not expired, it returns true.
 * If the nonce is expired or does not exist, it returns false.
 * After successful verification, the nonce is deleted to prevent replay attacks.
 */
// func isValidNonce(sessionID, nonce string) (error) {
// 	// Check if the nonce exists in Redis
// 	data, err := redis.GetSessionData(sessionID)
// 	if data.Nonce == "" || data.Nonce != nonce || err != nil {
// 		return fmt.Errorf("invalid nonce")
// 	}
// 	// Check TTL
// 	if data.TTL <= 0 {
// 		return fmt.Errorf("nonce %s is not valid or has expired", nonce)
// 	}
// 	return nil
// }

// ---------- secret key ----------

/**
 * Generates a new secret key for encrypting/decrypting data and HMAC operations.
 * Returns the key as a byte slice.
 */
func NewSecretKey() []byte {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}
	return key
}
