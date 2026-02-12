package redis

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	rdb                *redis.Client          // Redis client for storing nonces
	ctx                = context.Background() // Context for Redis operations
	ErrSessionNotFound = errors.New("session not found")
)

type SessionData struct {
	ID        string
	Nonce     string
	TTL       time.Duration
	SecretKey []byte
	Used      bool // whether the session has been used
}

/**
* InitRedis must be called before using SaveNonce, GetNonce, DeleteNonce
 */
func InitRedis() error {
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		addr = "redis:6379"
	}
	password := os.Getenv("REDIS_PASSWORD")

	rdb = redis.NewClient(&redis.Options{
		Addr:     addr,     // e.g. "redis:6379"
		Password: password, // "" if no password
		DB:       0,        // use default DB
	})

	// Check connection
	_, err := rdb.Ping(ctx).Result()
	if err != nil {
		return fmt.Errorf("failed to connect to redis: %w", err)
	}
	return nil
}

/**
* Saving / overriding nonce and secret key under <sessionID> in redis database
 */
func SaveSessionData(data SessionData) error {
	if rdb == nil {
		return fmt.Errorf("redis client not initialized")
	}
	if data.ID == "" || data.Nonce == "" || len(data.SecretKey) == 0 {
		return fmt.Errorf("invalid input")
	}
	key := "session:" + data.ID

	// TxPipeline to set multiple fields atomically
	// Redis HSet command to store nonce and secret key as hash fields
	// Set TTL for the entire hash
	_, err := rdb.TxPipelined(ctx, func(p redis.Pipeliner) error {
		// overwrite fields is allowed
		if err := p.HSet(ctx, key, "nonce", data.Nonce, "secret_key", data.SecretKey, "used", data.Used).Err(); err != nil {
			return err
		}
		// Set TTL for the session
		if data.TTL > 0 {
			if err := p.Expire(ctx, key, data.TTL).Err(); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to save session data: %w", err)
	}

	log.Printf("session %s saved (ttl=%s)", data.ID, data.TTL)
	return nil
}

/**
* Get Nonce and SecretKey from redis database by sessionID
 */
func GetSessionData(sessionID string) (SessionData, error) {
	if rdb == nil {
		return SessionData{}, fmt.Errorf("redis client not initialized")
	}
	if sessionID == "" {
		return SessionData{}, fmt.Errorf("empty sessionID")
	}

	key := "session:" + sessionID

	// Load hash fields
	m, err := rdb.HGetAll(ctx, key).Result()
	if err != nil {
		return SessionData{}, fmt.Errorf("failed to get session hash: %w", err)
	}

	// If the key does not exist or is empty
	if len(m) == 0 {
		return SessionData{}, ErrSessionNotFound
	}

	// Get TTL of the key
	ttl, err := rdb.TTL(ctx, key).Result()
	if err != nil {
		return SessionData{}, fmt.Errorf("failed to get session TTL: %w", err)
	}

	nonce, okNonce := m["nonce"]
	secret, okSecret := m["secret_key"]
	if !okNonce || !okSecret {
		// Hash exists, but fields do not => corrupted session
		return SessionData{}, ErrSessionNotFound
	}

	sessionData := SessionData{
		ID:        sessionID,
		Nonce:     nonce,
		SecretKey: []byte(secret),
		TTL:       ttl,
		Used:      m["used"] == "1" || m["used"] == "true",
	}
	return sessionData, nil
}

/**
* Mark session as used in redis database
 */
func MarkSessionAsUsed(sessionID string) error {
	if rdb == nil {
		return fmt.Errorf("redis client not initialized")
	}
	key := "session:" + sessionID

	// Set "used" field to true
	if err := rdb.HSet(ctx, key, "used", true).Err(); err != nil {
		return fmt.Errorf("failed to mark session as used: %w", err)
	}
	return nil
}

/**
* Check if session is marked as used in redis database
 */
func IsSessionUsed(sessionID string) (bool, error) {
	if rdb == nil {
		return false, fmt.Errorf("redis client not initialized")
	}
	key := "session:" + sessionID

	used, err := rdb.HGet(ctx, key, "used").Result()
	if err != nil {
		return false, fmt.Errorf("failed to get session used status: %w", err)
	}

	return used == "1" || used == "true", nil
}

/**
* Delete Nonce from redis database
* return: error message
 */
func DeleteSessionData(sessionID string) error {
	if rdb == nil {
		return fmt.Errorf("redis client not initialized (call InitRedis first)")
	}
	key := "session:" + sessionID
	result := rdb.Del(ctx, key)
	return result.Err()
}

/**
* Get all session IDs stored in Redis
 */
func GetAllSessionIDs() ([]string, error) {
	if rdb == nil {
		return nil, fmt.Errorf("redis client not initialized")
	}

	// ctx := context.Background()
	var cursor uint64
	var keys []string

	for {
		var scanKeys []string
		var err error
		// Scan for keys with pattern "session:*" 500 at a time
		scanKeys, cursor, err = rdb.Scan(ctx, cursor, "session:*", 500).Result()
		if err != nil {
			return nil, err
		}

		keys = append(keys, scanKeys...)

		if cursor == 0 { // done scanning
			break
		}
	}

	return keys, nil
}
