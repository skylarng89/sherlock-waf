// M9 acceptance 1 (API protection overhead). One documented POST /payments with
// a JSON body and a bearer token at a fixed arrival rate. run-api.sh runs it
// against a plain site and against the same route behind policy.api, and
// compares the two to get what the API layer adds.
import http from 'k6/http';
import { check } from 'k6';

const rate = Number(__ENV.RATE || 200);
const duration = __ENV.DURATION || '2m';
const target = __ENV.TARGET; // e.g. http://127.0.0.1:18102
const token = __ENV.TOKEN || '';

export const options = {
  scenarios: {
    api: {
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

// Same body, same headers for both sites so the only difference is the API module.
const body = JSON.stringify({ amount: 1250, currency: 'EUR' });

export default function () {
  const res = http.post(`${target}/payments`, body, {
    headers: {
      Host: __ENV.HOST_HEADER || 'api.localhost',
      'Content-Type': 'application/json',
      Accept: 'application/json',
      Authorization: `Bearer ${token}`,
    },
  });
  check(res, { 'status 201': (r) => r.status === 201 });
}
