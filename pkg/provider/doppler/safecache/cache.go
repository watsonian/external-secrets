package safecache

import (
	"sync"
	"time"
)

type SafeCache struct {
	mu    sync.Mutex
	cache map[string]*CacheEntry

	enabled bool
}

type CacheEntry struct {
	ETag          string
	Data          any
	LastCheckedAt time.Time
}

func NewCache() *SafeCache {
	return &SafeCache{cache: make(map[string]*CacheEntry), enabled: false}
}

func (sc *SafeCache) Enable() {
	sc.mu.Lock()
	sc.enabled = true
	sc.mu.Unlock()
}

func (sc *SafeCache) Disable() {
	sc.mu.Lock()
	sc.enabled = false
	sc.mu.Unlock()
}

func (sc *SafeCache) Enabled() bool {
	sc.mu.Lock()
	defer sc.mu.Unlock()
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
	sc.cache[cacheKey] = &CacheEntry{ETag: etag, LastCheckedAt: lastCheckedAt, Data: data}
	sc.mu.Unlock()
}
