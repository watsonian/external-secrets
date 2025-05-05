package safecache

import (
	"sync"
	"time"
)

var defaultCacheEntryTTL = 5 * time.Second

type SafeCache struct {
	mu            sync.Mutex
	cache         map[string]*CacheEntry
	cacheEntryTTL time.Duration

	enabled bool
}

type CacheEntry struct {
	ETag          string
	Data          any
	LastCheckedAt time.Time
	ttl           time.Duration
}

func NewCache() *SafeCache {
	return &SafeCache{cache: make(map[string]*CacheEntry), cacheEntryTTL: defaultCacheEntryTTL, enabled: false}
}

func (sc *SafeCache) Enable() {
	sc.mu.Lock()
	sc.enabled = true
	sc.mu.Unlock()
}

func (sc *SafeCache) Enabled() bool {
	return sc.enabled
}

func (sc *SafeCache) Read(cacheKey string) (*CacheEntry, bool) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	cacheEntry, cacheEntryFound := sc.cache[cacheKey]
	return cacheEntry, cacheEntryFound
}

func (sc *SafeCache) Write(cacheKey, etag string, lastCheckedAt time.Time, data any) {
	sc.mu.Lock()
	sc.cache[cacheKey] = &CacheEntry{ETag: etag, LastCheckedAt: lastCheckedAt, Data: data, ttl: sc.cacheEntryTTL}
	sc.mu.Unlock()
}

func (sc *SafeCache) CacheEntryTTL() time.Duration {
	return sc.cacheEntryTTL
}

func (sc *SafeCache) SetCacheEntryTTL(ttl time.Duration) {
	sc.mu.Lock()
	sc.cacheEntryTTL = ttl
	sc.mu.Unlock()
}

func (ce *CacheEntry) Expired() bool {
	return time.Since(ce.LastCheckedAt) > ce.ttl
}
