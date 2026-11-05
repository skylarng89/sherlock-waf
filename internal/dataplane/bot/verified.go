package bot

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// crawler describes a search engine that can be verified: its user-agent token
// and the DNS suffixes its crawlers' reverse DNS names end in.
type crawler struct {
	name     string
	uaToken  string
	suffixes []string
}

var crawlers = []crawler{
	{"googlebot", "googlebot", []string{".googlebot.com", ".google.com"}},
	{"bingbot", "bingbot", []string{".search.msn.com"}},
	{"applebot", "applebot", []string{".applebot.apple.com"}},
	{"duckduckbot", "duckduckbot", []string{".duckduckgo.com"}},
	{"yandex", "yandexbot", []string{".yandex.com", ".yandex.ru", ".yandex.net"}},
	{"baidu", "baiduspider", []string{".baidu.com", ".baidu.jp"}},
}

// claimedCrawler returns the crawler the user agent claims to be.
func claimedCrawler(ua string) (crawler, bool) {
	l := strings.ToLower(ua)
	for _, c := range crawlers {
		if strings.Contains(l, c.uaToken) {
			return c, true
		}
	}
	return crawler{}, false
}

// resolver is the DNS lookups the verification needs; tests substitute it.
type resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

type verdict int

const (
	unknown verdict = iota
	verified
	unverified
)

const (
	verdictTTL   = 24 * time.Hour
	maxVerdicts  = 50_000
	lookupBudget = 5 * time.Second
	queueSize    = 256
)

// verifier decides whether a client that claims to be a crawler really is one:
// reverse DNS must end in the crawler's domain and that name must resolve back
// to the same address. DNS is a network call, which the request path must
// never make, so a client whose address has not been checked yet is treated as
// unverified while the check runs in the background; the next request sees the answer.
type verifier struct {
	res resolver
	now func() time.Time

	mu       sync.Mutex
	cache    map[string]cached
	inflight map[string]bool
	queue    chan job
	once     sync.Once
}

type cached struct {
	v   verdict
	exp time.Time
}

type job struct {
	ip netip.Addr
	c  crawler
}

func newVerifier(res resolver) *verifier {
	return &verifier{res: res, now: time.Now, cache: map[string]cached{}, inflight: map[string]bool{}, queue: make(chan job, queueSize)}
}

var defaultVerifier = newVerifier(net.DefaultResolver)

func key(ip netip.Addr, c crawler) string { return c.name + "|" + ip.String() }

// check returns the cached verdict, starting a background check when there is none.
func (v *verifier) check(ip netip.Addr, c crawler) verdict {
	k := key(ip, c)
	v.mu.Lock()
	defer v.mu.Unlock()
	if e, ok := v.cache[k]; ok && v.now().Before(e.exp) {
		return e.v
	}
	if v.inflight[k] {
		return unknown
	}
	v.once.Do(func() { go v.worker() })
	select {
	case v.queue <- job{ip, c}:
		v.inflight[k] = true
	default: // the queue is full: stay unverified rather than block
	}
	return unknown
}

func (v *verifier) worker() {
	ctx := context.Background() // a background job: it has no request to inherit from
	for j := range v.queue {
		ok := v.verify(ctx, j.ip, j.c)
		res := unverified
		if ok {
			res = verified
		}
		k := key(j.ip, j.c)
		v.mu.Lock()
		delete(v.inflight, k)
		if len(v.cache) >= maxVerdicts {
			clear(v.cache)
		}
		v.cache[k] = cached{res, v.now().Add(verdictTTL)}
		v.mu.Unlock()
	}
}

func (v *verifier) verify(parent context.Context, ip netip.Addr, c crawler) bool {
	ctx, cancel := context.WithTimeout(parent, lookupBudget)
	defer cancel()
	names, err := v.res.LookupAddr(ctx, ip.String())
	if err != nil {
		return false
	}
	for _, n := range names {
		n = strings.TrimSuffix(strings.ToLower(n), ".")
		if !hasSuffixIn(n, c.suffixes) {
			continue
		}
		addrs, err := v.res.LookupHost(ctx, n)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if parsed, err := netip.ParseAddr(a); err == nil && parsed.Unmap() == ip.Unmap() {
				return true
			}
		}
	}
	return false
}

func hasSuffixIn(name string, suffixes []string) bool {
	for _, s := range suffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}
