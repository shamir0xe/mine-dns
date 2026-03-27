package dependencies

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/spf13/viper"
)

type cacheEntry[T any] struct {
	value    *T
	expireAt time.Time
}

type CacheStruct[T any] struct {
	sync.RWMutex
	data            map[string]cacheEntry[T]
	cleanupInterval time.Duration
	minTTL          time.Duration
}

func NewCache[T any](ctx context.Context, cfg *viper.Viper) *CacheStruct[T] {
	cache := &CacheStruct[T]{
		data:            make(map[string]cacheEntry[T]),
		cleanupInterval: cfg.GetDuration("cleanup-interval"),
		minTTL:          cfg.GetDuration("min-ttl"),
	}
	go cache.cleanup(ctx)
	return cache
}

func (c *CacheStruct[T]) Get(key string) (*T, bool) {
	c.RLock()
	entry, found := c.data[key]
	c.RUnlock()
	if found && time.Now().Before(entry.expireAt) {
		log.Printf("Cache hit for key: %s", key)
		return entry.value, true
	}
	log.Printf("Cache miss for key: %s", key)
	return nil, false
}

func (c *CacheStruct[T]) Set(key string, value *T, ttl time.Duration) {
	if ttl < c.minTTL {
		ttl = c.minTTL
	}
	c.Lock()
	c.data[key] = cacheEntry[T]{
		value:    value,
		expireAt: time.Now().Add(ttl),
	}
	c.Unlock()
	log.Printf("Set %s in cache with TTL %s", key, ttl)
}

func (c *CacheStruct[T]) cleanup(ctx context.Context) {
	log.Println("Cache cleanup goroutine started")

	ticker := time.NewTicker(c.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("Cache cleanup goroutine stopping")
			return
		case <-ticker.C:
			log.Println("Starting cache cleanup")
			c.Lock()
			now := time.Now()
			for key, entry := range c.data {
				if now.After(entry.expireAt) {
					delete(c.data, key)
				}
			}
			c.Unlock()
			log.Println("Cache cleanup completed")
		}
	}

}
