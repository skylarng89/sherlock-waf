// M11 acceptance 1 (credential stuffing). 50 usernames x 1,000 passwords from
// 200 source addresses against the protected login, while one ordinary customer
// signs in once a second from their own address and browser. run-login.sh starts
// Sherlock with login_protection and reads the summary this script exports.
//
// What must hold: every account is guessed at only a few times before it is
// challenged, almost all of the 50,000 guesses are refused before they reach the
// origin, and the ordinary customer always gets in.
import http from 'k6/http';
import { check } from 'k6';
import { Counter, Rate } from 'k6/metrics';

const target = __ENV.TARGET; // e.g. http://127.0.0.1:18202
const host = __ENV.HOST_HEADER || 'login.localhost';
const users = 50;
const passwords = Number(__ENV.PASSWORDS || 1000);
const addresses = Number(__ENV.ADDRESSES || 200);

const reached = new Counter('attack_reached'); // guesses the origin saw and rejected (401)
const refused = new Counter('attack_refused'); // guesses refused by Sherlock (403 or 429)
const unexpected = new Counter('attack_unexpected'); // anything else, including a guess that succeeded
const customerOK = new Rate('customer_login_ok');

export const options = {
  scenarios: {
    attack: {
      executor: 'shared-iterations',
      exec: 'attack',
      vus: 50,
      iterations: users * passwords,
      maxDuration: '15m',
    },
    customer: {
      executor: 'constant-arrival-rate',
      exec: 'customer',
      rate: 1,
      timeUnit: '1s',
      duration: __ENV.CUSTOMER_DURATION || '3m',
      preAllocatedVUs: 2,
      maxVUs: 10,
    },
  },
  summaryTrendStats: ['min', 'med', 'p(95)', 'p(99)', 'max'],
  thresholds: {
    customer_login_ok: ['rate==1'],
    attack_unexpected: ['count==0'],
  },
};

function login(xff, ua, user, pass) {
  return http.post(`${target}/api/login`, { email: user, password: pass }, {
    headers: { Host: host, 'X-Forwarded-For': xff, 'User-Agent': ua },
    redirects: 0,
    responseCallback: http.expectedStatuses(200, 401, 403, 429),
  });
}

export function attack() {
  const i = __ITER; // unique per iteration across the scenario
  const xff = `10.${100 + Math.floor((i % addresses) / 250)}.${Math.floor((i % addresses) / 50)}.${(i % 50) + 1}`;
  const res = login(xff, `stuffing-kit/${i % users}`, `user${i % users}@bank.test`, `guess-${i}`);
  if (res.status === 401) reached.add(1);
  else if (res.status === 403 || res.status === 429) refused.add(1);
  else unexpected.add(1);
}

export function customer() {
  const res = login('203.0.113.200', 'Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/130.0', 'customer@bank.test', 'correct horse');
  customerOK.add(res.status === 200);
  check(res, { 'customer signed in': (r) => r.status === 200 });
}
