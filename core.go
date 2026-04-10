// package dnscache ...
package dnscache

import (
	"net"
	"runtime"
	"sync"
	"time"
	"sync/atomic"
)

const (
	_empty       = ""
	_sep         = "#"
	_mx          = "MX"
	_ns          = "NS"
	_srv         = "SRV"
	_txt         = "TXT"
	_ptr         = "PTR"
	_cname       = "CNAME"
	_expireEvery = 60 * time.Minute // run expire process ever 20 minutes
)

var (
	scale = runtime.NumCPU() * 10
	// IP Cache
	bgIP                       sync.WaitGroup
	dnsIPMap                   = make(map[string][]net.IP, scale)
	dnsIPExpire                = make(map[string]int64, scale)
	dnsIPChan                  = make(chan dnsIP, scale)
	dnsIPChanExpire            = make(chan dnsIP, scale*25)
	dnsIPLock, dnsIPLockExpire sync.RWMutex
	// Host Cache
	bgHost                         sync.WaitGroup
	dnsHostMap                     = make(map[string]any, scale)
	dnsHostExpire                  = make(map[string]int64, scale)
	dnsHostChan                    = make(chan dnsHost, scale)
	dnsHostChanExpire              = make(chan dnsHost, scale*25)
	dnsHostLock, dnsHostLockExpire sync.RWMutex
	maxEntries   int
	maxEntriesMu sync.RWMutex
	globalMinTTL int64 = 24 * 60 * 60
	GlobalStatsQueries uint64
	GlobalStatsHits    uint64
	GlobalStatsMisses  uint64
)

// dnsIP ...
type dnsIP struct {
	host string
	ip   []net.IP
}

// dnsHost ...
type dnsHost struct {
	host  string
	addrs any
}

func getIP(host string) ([]net.IP, bool) {
	dnsIPLock.Lock()
	if ip, ok := dnsIPMap[host]; ok {
		dnsIPLock.Unlock()
		atomic.AddUint64(&StatsHits, 1) 
		atomic.AddUint64(&StatsQueries, 1)
		return ip, true
	}
	dnsIPLock.Unlock()
	atomic.AddUint64(&StatsMisses, 1) 
	atomic.AddUint64(&StatsQueries, 1)
	return []net.IP{}, false
}

func getHost(host string) (any, bool) {
	dnsHostLock.Lock()
	if addrs, ok := dnsHostMap[host]; ok {
		dnsHostLock.Unlock()
		atomic.AddUint64(&StatsHits, 1)
		atomic.AddUint64(&StatsQueries, 1)
		return addrs, true
	}
	dnsHostLock.Unlock()
	atomic.AddUint64(&StatsMisses, 1)
	atomic.AddUint64(&StatsQueries, 1)
	return nil, false
}

// intit ...
func init() {
        if maxEntries == 0 {
           	 	maxEntries = 10000
	}
	spinUpCacheWriter()
	spinUpExpireWriter()
	spinUpExpireGC()
}

// spinUpCacheWriter ...
func spinUpCacheWriter() {
	go func() {
	    for c := range dnsIPChan {
	    	if shouldEvictIP() {
		    	evictOneIP()
	    	}
	    	dnsIPLock.Lock()
     		dnsIPMap[c.host] = c.ip
	    	dnsIPLock.Unlock()
    		dnsIPChanExpire <- c
    	}
    }()
	go func() {
    	for c := range dnsHostChan {
    		if shouldEvictHost() {
	    		evictOneHost()
    		}
    		dnsHostLock.Lock()
	    	dnsHostMap[c.host] = c.addrs
    		dnsHostLock.Unlock()
    		dnsHostChanExpire <- c
    	}
    }()
}

// spinUpExpireWriter ...
func spinUpExpireWriter() {
	go func() {
		for c := range dnsIPChanExpire {
			dnsIPLockExpire.Lock()
			dnsIPExpire[c.host] = time.Now().Unix() + atomic.LoadInt64(&globalMinTTL)
			dnsIPLockExpire.Unlock()
		}
	}()
	go func() {
		for c := range dnsHostChanExpire {
			dnsHostLockExpire.Lock()
			dnsHostExpire[c.host] = time.Now().Unix() + atomic.LoadInt64(&globalMinTTL)
			dnsHostLockExpire.Unlock()
		}
	}()
}

// spinUpExpireGC ...
func spinUpExpireGC() {
	go func() {
		for {
			time.Sleep(_expireEvery)
			now := time.Now().Unix()
			{
				expired := []string{}
				dnsIPLockExpire.Lock()
				for k, v := range dnsIPExpire {
					if v < now {
						expired = append(expired, k)
					}
				}
				dnsIPLockExpire.Unlock()
				dnsIPLock.Lock()
				for _, e := range expired {
					delete(dnsIPMap, e)
				}
				dnsIPLock.Unlock()
			}
			{
				expired := []string{}
				dnsHostLockExpire.Lock()
				for k, v := range dnsHostExpire {
					if v < now {
						expired = append(expired, k)
					}
				}
				dnsHostLockExpire.Unlock()
				dnsHostLock.Lock()
				for _, e := range expired {
					delete(dnsHostMap, e)
				}
				dnsHostLock.Unlock()
			}
		}
	}()
}

// cleanCacheAll ...
func cleanCacheAll() {
	cleanIPCache()
	cleanHostCache()
}

// cleanIPCache ...
func cleanIPCache() {
	bgIP.Add(2)
	// lookup table
	go func() {
		dnsIPLock.Lock()
		for host := range dnsIPMap {
			delete(dnsIPMap, host)
		}
		bgIP.Done()
	}()
	go func() { // expire table
		dnsIPLockExpire.Lock()
		for host := range dnsIPExpire {
			delete(dnsIPExpire, host)
		}
		dnsIPLockExpire.Unlock()
		bgIP.Done()
	}()
	bgIP.Wait()
	dnsIPLock.Unlock()
}

// cleanHostCache ...
func cleanHostCache() {
	bgHost.Add(2)
	go func() { // lookup table
		dnsHostLock.Lock()
		for host := range dnsHostMap {
			delete(dnsHostMap, host)
		}
		bgHost.Done()
	}()
	go func() { // expire table
		dnsHostLockExpire.Lock()
		for host := range dnsHostExpire {
			delete(dnsHostExpire, host)
		}
		bgHost.Done()
	}()
	dnsHostLockExpire.Unlock()
	bgHost.Wait()
	dnsHostLock.Unlock()
}

func SetMaxEntries(n int) {
	maxEntriesMu.Lock()
	defer maxEntriesMu.Unlock()
	maxEntries = n
}

func SetCacheTTL(seconds int64) {
	atomic.StoreInt64(&globalMinTTL, seconds)
}

func shouldEvictIP() bool {
	maxEntriesMu.RLock()
	limit := maxEntries
	maxEntriesMu.RUnlock()
	if limit <= 0 {
		return false
	}
	dnsIPLock.RLock()
	defer dnsIPLock.RUnlock()
	return len(dnsIPMap) >= limit
}

func evictOneIP() {
	dnsIPLock.Lock()
	defer dnsIPLock.Unlock()
	for k := range dnsIPMap {
		delete(dnsIPMap, k)
		dnsIPLockExpire.Lock()
		delete(dnsIPExpire, k)
		dnsIPLockExpire.Unlock()
		break
	}
}

func shouldEvictHost() bool {
	maxEntriesMu.RLock()
	limit := maxEntries
	maxEntriesMu.RUnlock()
	if limit <= 0 {
		return false
	}
	dnsHostLock.RLock()
	defer dnsHostLock.RUnlock()
	return len(dnsHostMap) >= limit
}

func evictOneHost() {
	dnsHostLock.Lock()
	defer dnsHostLock.Unlock()
	for k := range dnsHostMap {
		delete(dnsHostMap, k)
		break
	}
}

func GetCacheEntries() int {
	dnsIPLock.RLock()
	ipCount := len(dnsIPMap)
	dnsIPLock.RUnlock()

	dnsHostLock.RLock()
	hostCount := len(dnsHostMap)
	dnsHostLock.RUnlock()

	return ipCount + hostCount
}
