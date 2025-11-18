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
	rdb *redis.Client          // Redis client for storing nonces
	ctx = context.Background() // Context for Redis operations
	ErrSessionNotFound = errors.New("session not found")
)

type SessionData struct {
	ID       string
	Nonce    string
	TTL      time.Duration
	SecretKey []byte
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
		DB:       0,      // use default DB
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
func SaveSessionData(data SessionData) (error) {
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
		if err := p.HSet(ctx, key, "nonce", data.Nonce, "secret_key", data.SecretKey).Err(); err != nil {
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

	log.Printf("session %s saved (ttl=%s)", truncateID(data.ID), data.TTL)
	return nil
}

/**
* Get session data from redis database
* return: SessionData struct and error message
 */
func GetSessionData(sessionID string) (SessionData, error) {
	if rdb == nil {
		return SessionData{}, fmt.Errorf("redis client not initialized")
	}
	if sessionID == "" {
		return SessionData{}, fmt.Errorf("empty sessionID")
	}

	// TODO: Decrypt value with TEE Key

	// Get the nonce value from Redis
	val, err := rdb.Get(ctx, nonce).Result()
	if err == redis.Nil {
		return "", 0, fmt.Errorf("nonce %s does not exist", nonce)
	} else if err != nil {
		return "", 0, err
	}

	// get TTL of the nonce
	ttl, err := rdb.TTL(ctx, nonce).Result()
	if err != nil {
		return SessionData{}, err
	}
	if len(m) == 0 {
		// Key exists, but no hash? (or just expired)
		return SessionData{}, ErrSessionNotFound
	}

	sessionData := SessionData{
		ID:       sessionID,
		Nonce:    m["nonce"],
		SecretKey: []byte(m["secret_key"]),
		TTL:      ttl,
	}
	return sessionData, nil
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

// --- helper functions ---
func truncateID(id string) string {
	if len(id) <= 8 { return id }
	return id[:4] + "…" + id[len(id)-4:]
}