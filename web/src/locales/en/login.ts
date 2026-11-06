// Login protection tab (M11-T3). Keys are addressed as login.<key>.
export default {
  tab: 'Login protection',
  title: 'Login protection',
  description:
    'Detect credential stuffing on your login endpoints and challenge or block the clients behind it.',
  saved: 'Login protection saved',
  readOnly: 'You can view this policy but not change it.',
  sections: { general: 'Login protection', endpoints: 'Login endpoints', limits: 'Limits' },
  enabled: { label: 'Login protection', switch: 'Watch failed logins on this site' },
  mode: {
    detect:
      'This site is in detect mode. Login findings are recorded but not enforced: no client is challenged or blocked.',
    off: 'This site is in off mode. Login protection does nothing until the site is switched to detect or block.',
  },
  privacy:
    'Usernames are never stored in the clear: Sherlock keeps only a keyed hash in memory to count failures per account, and never writes a username, a hash or a password to events, logs or exports.',
  noEndpoints:
    'No login endpoint is declared, so nothing is watched yet. Add the request your login form sends.',
  inherited: 'Inherited: {value}',
  builtin: 'Default: {value}',
  endpoints: {
    help: 'A failed login is an upstream response with one of the failure statuses. Declaring an endpoint that does not return a failure status for a wrong password counts nothing.',
    empty: 'No endpoints declared at this level.',
    legend: 'Endpoint {n}',
    add: 'Add endpoint',
    remove: 'Remove endpoint {n}',
    path: { label: 'Path', help: 'A path or glob that starts with /, such as /api/login.' },
    method: { label: 'Method', default: 'Default (POST)' },
    username: {
      label: 'Username field',
      help: 'The form field (email) or JSON pointer (/user/email) that holds the username in the request body.',
    },
    statuses: {
      label: 'Failure statuses',
      help: 'Comma separated upstream statuses that mean the login failed. Default 401, 403.',
    },
  },
  thresholds: {
    help: 'Failures allowed per window before the action applies. Counts are kept per client address, per username and per device.',
    perIp: { label: 'Failures per client address' },
    perUsername: { label: 'Failures per username' },
    perDevice: { label: 'Failures per device' },
    window: { label: 'Window', help: 'A duration from 1m to 24h, such as 10m or 1h.' },
  },
  action: {
    label: 'Action over a threshold',
    help: 'Challenge asks the client to pass a proof-of-work challenge and needs the Bot tab enabled; without it a challenge acts as a block.',
    challenge: 'Challenge',
    block: 'Block',
    log: 'Log only',
  },
  errors: {
    action: 'Choose challenge, block or log.',
    tooManyEndpoints: 'At most 20 endpoints.',
    path: 'The path must start with /.',
    method: 'Use an HTTP method such as POST.',
    usernameRequired: 'Name the form field or JSON pointer that holds the username.',
    usernameInvalid: 'At most 128 characters, without line breaks.',
    statuses: 'Enter up to 20 HTTP statuses between 100 and 599, separated by commas.',
    threshold: 'Enter a whole number from 1 to 100000.',
    window: 'Enter a duration from 1m to 24h, such as 10m.',
  },
}
