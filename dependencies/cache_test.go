package dependencies

import (
	"testing"
	"time"
)

func newTestLogger() *SessionLogger {
	return &SessionLogger{color: ""}
}

func newTestCache(minTTL time.Duration) *CacheStruct[string] {
	return &CacheStruct[string]{
		data:            make(map[string]cacheEntry[string]),
		cleanupInterval: time.Minute,
		minTTL:          minTTL,
	}
}

func TestCache_Miss(t *testing.T) {
	c := newTestCache(time.Second)
	_, found := c.Get("missing", newTestLogger())
	if found {
		t.Error("expected miss on empty cache")
	}
}

func TestCache_SetGet(t *testing.T) {
	c := newTestCache(time.Second)
	val := "hello"
	c.Set("k", &val, time.Minute, newTestLogger())
	got, found := c.Get("k", newTestLogger())
	if !found {
		t.Fatal("expected hit after Set")
	}
	if *got != val {
		t.Errorf("got %q, want %q", *got, val)
	}
}

func TestCache_Expiry(t *testing.T) {
	c := newTestCache(time.Millisecond)
	val := "expiring"
	c.Set("k", &val, time.Millisecond, newTestLogger())
	time.Sleep(10 * time.Millisecond)
	_, found := c.Get("k", newTestLogger())
	if found {
		t.Error("expected expired entry to be a miss")
	}
}

func TestCache_MinTTLEnforced(t *testing.T) {
	c := newTestCache(time.Hour)
	val := "v"
	// TTL of 1ms is below minTTL of 1h — should be bumped up
	c.Set("k", &val, time.Millisecond, newTestLogger())
	_, found := c.Get("k", newTestLogger())
	if !found {
		t.Error("expected minTTL to keep entry alive")
	}
}

func TestCache_Overwrite(t *testing.T) {
	c := newTestCache(time.Second)
	first, second := "first", "second"
	c.Set("k", &first, time.Minute, newTestLogger())
	c.Set("k", &second, time.Minute, newTestLogger())
	got, found := c.Get("k", newTestLogger())
	if !found {
		t.Fatal("expected hit")
	}
	if *got != second {
		t.Errorf("expected overwritten value %q, got %q", second, *got)
	}
}
