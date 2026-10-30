// M2-T9(b): throughput step. One constant-arrival-rate step at RATE rps; run.sh
// walks the rate upwards and stops at the first step whose p99 exceeds 50 ms
// (or that drops requests), reporting the last good rate (NFR-2).
import http from 'k6/http';
import { check } from 'k6';

const rate = Number(__ENV.RATE || 1000);
const target = __ENV.TARGET;

export const options = {
  scenarios: {
    step: {
      executor: 'constant-arrival-rate',
      rate,
      timeUnit: '1s',
      duration: __ENV.DURATION || '20s',
      preAllocatedVUs: 100,
      maxVUs: 2000,
    },
  },
  summaryTrendStats: ['med', 'p(95)', 'p(99)', 'max'],
};

export default function () {
  const res = http.get(`${target}/products?category=shoes&page=2&sort=price`, {
    headers: { Host: __ENV.HOST_HEADER || 'bench.localhost', 'User-Agent': 'Mozilla/5.0 Chrome/120.0', Accept: 'text/html' },
  });
  check(res, { 'status 200': (r) => r.status === 200 });
}
