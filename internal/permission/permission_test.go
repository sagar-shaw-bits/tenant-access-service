package permission

import (
	"testing"
	"time"
)

func TestCacheStoresAndExpiresMembershipPermissions(t *testing.T) {
	cache := NewCache(10 * time.Millisecond)
	cache.Set("membership-a", []string{"user:read", "role:update"}, 0)
	if !cache.Has("membership-a", "user:read") {
		t.Fatal("expected permission to be cached")
	}
	if cache.Has("membership-b", "user:read") {
		t.Fatal("permissions must not be shared across memberships")
	}
	time.Sleep(20 * time.Millisecond)
	if _, ok := cache.Get("membership-a"); ok {
		t.Fatal("expected expired entry to be removed")
	}
}

func TestCacheDelete(t *testing.T) {
	cache := NewCache(time.Minute)
	cache.Set("membership-a", []string{"role:read"}, 0)
	cache.Delete("membership-a")
	if _, ok := cache.Get("membership-a"); ok {
		t.Fatal("expected deleted entry to be absent")
	}
}
