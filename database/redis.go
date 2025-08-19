package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	rdb *redis.Client          // Redis client for storing nonces
	ctx = context.Background() // Context for Redis operations
)

const nonceTTL = 5 * time.Minute

/**
* InitRedis must be called before using SaveNonce, GetNonce, DeleteNonce
 */
func InitRedis(addr, password string, db int) error {
	rdb = redis.NewClient(&redis.Options{
		Addr:     addr,     // e.g. "localhost:6379"
		Password: password, // "" if no password
		DB:       db,       // 0 = default DB
	})

	// Check connection
	_, err := rdb.Ping(ctx).Result()
	if err != nil {
		return fmt.Errorf("failed to connect to redis: %w", err)
	}
	return nil
}

/**
* Saving Nonce in redis database
* return: Flag for success and error message
 */
func SaveNonce(nonce string) (bool, string) {
	if rdb == nil {
		return false, "redis client not initialized (call InitRedis first)"
	}

	err := rdb.Set(ctx, nonce, "valid", nonceTTL).Err()
	if err != nil {
		// return error message
		return false, err.Error()
	}

	// TODO Debug log for successful nonce storage
	fmt.Printf("Nonce %s saved successfully with TTL %v\n", nonce, nonceTTL)

	return true, ""
}

/**
* Get Nonce from redis database
* return: Nonce value, TTL and error message
 */
func GetNonce(nonce string) (string, time.Duration, error) {
	if rdb == nil {
		return "", 0, fmt.Errorf("redis client not initialized (call InitRedis first)")
	}

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
		return "", 0, fmt.Errorf("failed to get TTL for nonce %s: %w", nonce, err)
	}
	if ttl <= 0 {
		return "", ttl, fmt.Errorf("nonce %s has expired", nonce)
	}
	return val, ttl, nil
}

/**
* Delete Nonce from redis database
* return: error message
 */
func DeleteNonce(nonce string) error {
	if rdb == nil {
		return fmt.Errorf("redis client not initialized (call InitRedis first)")
	}

	// Delete the nonce from Redis
	err := rdb.Del(ctx, nonce).Err()
	if err != nil {
		return fmt.Errorf("failed to delete nonce %s: %w", nonce, err)
	}
	return nil
}
