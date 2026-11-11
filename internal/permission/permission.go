package permission

import (
	"sync"
	"time"
)

type Permission struct {
	ID       string `json:"id"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

type Cache struct {
	mu    sync.RWMutex
	items map[string]cacheEntry
	ttl   time.Duration
}

type cacheEntry struct {
	value     map[string]struct{}
	expiresAt time.Time
}

func NewCache(ttl time.Duration) *Cache {
	return &Cache{items: make(map[string]cacheEntry), ttl: ttl}
}

func (c *Cache) Get(key string) ([]string, bool) {
	c.mu.RLock()
	entry, ok := c.items[key]
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expiresAt) {
		c.mu.Lock()
		delete(c.items, key)
		c.mu.Unlock()
		return nil, false
	}
	permissions := make([]string, 0, len(entry.value))
	for permission := range entry.value {
		permissions = append(permissions, permission)
	}
	return permissions, true
}

func (c *Cache) Set(key string, permissions []string, ttl time.Duration) {
	set := make(map[string]struct{}, len(permissions))
	for _, permission := range permissions {
		set[permission] = struct{}{}
	}
	c.mu.Lock()
	if ttl <= 0 {
		ttl = c.ttl
	}
	c.items[key] = cacheEntry{value: set, expiresAt: time.Now().Add(ttl)}
	c.mu.Unlock()
}

func (c *Cache) Delete(key string) {
	c.mu.Lock()
	delete(c.items, key)
	c.mu.Unlock()
}

func (c *Cache) Has(key, permission string) bool {
	permissions, ok := c.Get(key)
	if !ok {
		return false
	}
	for _, value := range permissions {
		if value == permission {
			return true
		}
	}
	return false
}
