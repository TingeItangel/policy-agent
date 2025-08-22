package security

import (
	"fmt"
	redis "policy-agent/database"

	"github.com/google/uuid"
)

/**
 * This handler generates a unique nonce for the client to use in subsequent requests.
 * The nonce is stored in Redis with an expiration time to prevent replay attacks.
 * The client can retrieve this nonce and include it in their requests to ensure they are valid.
 */
func GetNewNonce() (bool, string) {
	// Generate a random UUID nonce
	nonce := uuid.New().String()

	// Call saveNonce to store the nonce in Redis with a TTL
	success, errMsg := redis.SaveNonce(nonce)
	if !success {
		// TODO: Log error in ERROR LOG
		fmt.Printf("Error to get nonce.  %v \n", errMsg)

		// http.Error(w, "Failed to save nonce: "+errMsg, http.StatusInternalServerError)
		return false, ""
	}

	return true, nonce
}

/**
 * This function checks if the provided nonce is valid.
 * It retrieves the nonce from Redis and checks its TTL.
 * If the nonce exists and is not expired, it returns true.
 * If the nonce is expired or does not exist, it returns false.
 * After successful verification, the nonce is deleted to prevent replay attacks.
 */
func isValidNonce(nonce string) (bool, string) {
	// Check if the nonce exists in Redis
	val, ttl, err := redis.GetNonce(nonce)
	if val == "" || err != nil {
		if err != nil {
			return false, "Error retrieving nonce: " + err.Error()
		}
		return false, "Nonce does not exist"
	}
	// Check TTL
	if ttl <= 0 {
		return false, "Nonce is not valid or has expired"
	}

	if val != "valid" {
		return false, "Nonce is not valid"
	}
	// DEBUG - log.Println("Nonce validation successful, nonce deleted:", nonce)
	// If we reach here, the nonce is valid
	return true, ""
}

func deleteNonce(nonce string) error {
	err := redis.DeleteNonce(nonce)
	if err != nil {
		// TODO Add Log Entry
		fmt.Printf("Error to delete nonce.  %v \n", err)
	}
	return err
	// TODO: Make a Log Entry here for successful nonce validation and Nonce deletion
}
