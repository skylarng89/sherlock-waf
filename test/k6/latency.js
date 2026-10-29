// M2-T9(a): latency. A 1 KB GET at a fixed arrival rate (default 200 rps for
// 2 minutes). Run once against the origin and once through Sherlock; run.sh
// compares the two to get the latency Sherlock adds (NFR-1).
import http from 'k6/http';
import { check } from 'k6';

const rate = Number(__ENV.RATE || 200);
const duration = __ENV.DURATION || '2m';
const target = __ENV.TARGET; // e.g. http://127.0.0.1:18101

export const options = {
  scenarios: {
    latency: {
      executor: 'constant-arrival-rate',
      rate,
      timeUnit: '1s',
      duration,
      preAllocatedVUs: 50,
      maxVUs: 400,
    },
  },
  summaryTrendStats: ['min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max', 'avg'],
  thresholds: { http_req_failed: ['rate<0.001'] },
};

export default function () {
  // Ordinary browser-like request with a few benign query parameters, so the
  // WAF does real work (headers + arguments) rather than seeing an empty request.
  const res = http.get(`${target}/products?category=shoes&page=2&sort=price`, {
    headers: {
      Host: __ENV.HOST_HEADER || 'bench.localhost',
      'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0',
      Accept: 'text/html,application/xhtml+xml',
      'Accept-Language': 'en-US,en;q=0.9',
    },
  });
  check(res, { 'status 200': (r) => r.status === 200, '1 KB body': (r) => r.body.length === 1024 });
}
