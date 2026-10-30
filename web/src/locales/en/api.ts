// API protection tab (M9-T6). Keys are addressed as api.<key>.
export default {
  tab: 'API',
  description:
    'Check requests against an OpenAPI document, validate bearer tokens and require client certificates.',
  saved: 'API protection saved',
  uploadFailed: 'The upload failed.',
  readOnly: 'You can view this policy but not change it.',
  sections: {
    general: 'OpenAPI conformance',
    jwt: 'Token validation (JWT)',
    mtls: 'Client certificates (mutual TLS)',
    uploads: 'Uploads',
    endpoints: 'Endpoints',
  },
  enabled: { label: 'API protection', switch: 'Check requests to this site' },
  actions: { log: 'Log only', block: 'Block' },
  docs: {
    label: 'OpenAPI document',
    help: 'Requests are checked against this document. Without one only tokens and certificates are checked.',
    none: 'None',
    uploaded: 'Document stored, {count} endpoints',
    uploadTitle: 'Upload an OpenAPI document',
    id: 'Identifier',
    idHelp: 'Lowercase letters, digits and hyphens.',
    name: 'Name',
    file: 'File',
    fileHelp:
      'OpenAPI 3.0 or 3.1, JSON or YAML, up to 4 MiB. References to other files are not followed.',
    upload: 'Upload document',
  },
  unknownPath: {
    label: 'Undocumented path or method',
    help: 'Block requests the document does not describe. In detect mode this only logs.',
  },
  schemaViolation: {
    label: 'Schema violation',
    help: 'Block documented requests whose parameters or body break the schema. In detect mode this only logs.',
  },
  jwt: {
    help: 'The first rule that matches a request applies. Tokens are verified with RS, PS, ES or EdDSA keys; HS algorithms are only accepted with a configured secret.',
    empty: 'No token rules yet.',
    add: 'Add rule',
    remove: 'Remove rule {n}',
    legend: 'Rule {n}',
    paths: { label: 'Paths', help: 'Comma separated, for example /api/*, /payments' },
    methods: { label: 'Methods', help: 'Comma separated. Empty means every method.' },
    source: { label: 'Key source' },
    sources: {
      jwks_url: 'JWKS URL',
      public_key_pem: 'Public key (PEM)',
      hmac_secret_env: 'Shared secret variable',
    },
    sourceHelp: {
      jwks_url:
        'https only. Keys are fetched in the background and rotate automatically. Internal addresses are refused.',
      public_key_pem: 'An RSA, ECDSA or Ed25519 public key.',
      hmac_secret_env:
        'Name of an environment variable on the node holding a secret of at least 32 bytes.',
    },
    issuer: { label: 'Issuer (iss)' },
    audiences: {
      label: 'Audiences (aud)',
      help: 'Comma separated. A token must carry one of them.',
    },
    clockSkew: { label: 'Clock skew', help: 'For example 30s. Up to 5m.' },
    optional: 'Let requests without a token through (a token that is sent must still be valid)',
    action: {
      label: 'When the token is missing or invalid',
      help: 'In detect mode this only logs.',
    },
  },
  mtls: {
    help: 'The site asks clients for a certificate and verifies one that is offered; the paths below refuse requests without a verified certificate.',
    none: 'No CA selected',
    uploaded: 'CA bundle stored',
    uploadTitle: 'Upload a CA bundle',
    pem: 'CA certificates (PEM)',
    pemHelp: 'Certificates only, never private keys.',
    upload: 'Upload CA bundle',
    ca: { label: 'Client CA' },
    paths: {
      label: 'Paths that require a certificate',
      help: 'Comma separated, for example /open-banking/*',
    },
  },
  endpoints: {
    help: 'Schema violations seen on each documented endpoint in the last 24 hours.',
    caption: 'Documented endpoints and their schema violations',
    method: 'Method',
    path: 'Path',
    violations: 'Violations (24 h)',
    undocumented: 'Requests for undocumented paths or methods (24 h)',
    noDoc: 'Choose an OpenAPI document to see its endpoints.',
    loadFailed: 'Endpoint counts could not be loaded.',
  },
}
