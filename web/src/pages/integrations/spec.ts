// Form specs for the built-in exporter types and notification channels, and the
// mapping between a flat form model and the nested settings document the API
// stores. The backend validates; these only decide which inputs to render.

/** What the API shows instead of a stored secret; sending it back keeps the stored value. */
export const MASK = '********'

export type FieldKind =
  | 'text'
  | 'secret'
  | 'select'
  | 'bool'
  | 'number'
  | 'textarea'
  | 'list'
  | 'headers'
  /** A configured site id, chosen from the site list. */
  | 'site'

export interface FieldSpec {
  /** Dotted path into the settings document, e.g. `tls.ca_pem`. */
  path: string
  kind: FieldKind
  /** i18n key suffix under `integrations.fields`. */
  label: string
  help?: boolean
  required?: boolean
  mono?: boolean
  options?: string[]
  default?: string | number | boolean
}

export type Settings = Record<string, unknown>
export type Model = Record<string, string | number | boolean | string[] | undefined>

const tls: FieldSpec[] = [
  { path: 'tls.server_name', kind: 'text', label: 'tlsServerName' },
  { path: 'tls.ca_pem', kind: 'textarea', label: 'tlsCaPem', help: true, mono: true },
]

export const EXPORTER_SPECS: Record<string, FieldSpec[]> = {
  syslog: [
    {
      path: 'network',
      kind: 'select',
      label: 'network',
      options: ['udp', 'tcp', 'tls'],
      default: 'tcp',
      required: true,
    },
    { path: 'address', kind: 'text', label: 'address', help: true, required: true, mono: true },
    { path: 'format', kind: 'select', label: 'format', options: ['cef', 'json'], default: 'cef' },
    { path: 'facility', kind: 'number', label: 'facility', help: true, default: 16 },
    { path: 'app_name', kind: 'text', label: 'appName', default: 'sherlock' },
    {
      path: 'framing',
      kind: 'select',
      label: 'framing',
      options: ['octet', 'newline'],
      default: 'octet',
      help: true,
    },
    ...tls,
  ],
  webhook: [
    { path: 'url', kind: 'secret', label: 'url', help: true, required: true },
    { path: 'hmac_secret', kind: 'secret', label: 'hmacSecret', help: true, required: true },
    { path: 'headers', kind: 'headers', label: 'headers', help: true },
    { path: 'allow_http', kind: 'bool', label: 'allowHttp', help: true },
  ],
  otlp: [
    { path: 'endpoint', kind: 'text', label: 'endpoint', help: true, required: true, mono: true },
    {
      path: 'protocol',
      kind: 'select',
      label: 'protocol',
      options: ['http', 'grpc'],
      default: 'http',
    },
    { path: 'headers', kind: 'headers', label: 'headers', help: true },
    { path: 'tls.ca_pem', kind: 'textarea', label: 'tlsCaPem', help: true, mono: true },
  ],
}

export const ALERT_KINDS = [
  'blocks_threshold',
  'new_country',
  'cert_expiring',
  'feed_failure',
  'events_dropped',
  'upstream_unhealthy',
] as const

export const COOLDOWN_MIN = 60
export const COOLDOWN_MAX = 604_800
export const COOLDOWN_DEFAULT = 900

const siteField: FieldSpec = { path: 'site_id', kind: 'site', label: 'siteId', help: true }

export const ALERT_PARAM_SPECS: Record<string, FieldSpec[]> = {
  blocks_threshold: [
    siteField,
    {
      path: 'threshold',
      kind: 'number',
      label: 'threshold',
      help: true,
      required: true,
      default: 100,
    },
    {
      path: 'window_seconds',
      kind: 'number',
      label: 'windowSeconds',
      help: true,
      required: true,
      default: 300,
    },
  ],
  new_country: [
    siteField,
    {
      path: 'window_seconds',
      kind: 'number',
      label: 'windowSeconds',
      help: true,
      required: true,
      default: 3600,
    },
    {
      path: 'baseline_seconds',
      kind: 'number',
      label: 'baselineSeconds',
      help: true,
      required: true,
      default: 604800,
    },
  ],
  cert_expiring: [
    { path: 'days', kind: 'number', label: 'days', help: true, required: true, default: 14 },
  ],
  feed_failure: [],
  events_dropped: [],
  upstream_unhealthy: [siteField],
}

export const CHANNEL_TYPES = ['smtp', 'webhook', 'slack', 'teams'] as const

const urlFields: FieldSpec[] = [
  { path: 'url', kind: 'secret', label: 'url', help: true, required: true },
  { path: 'allow_http', kind: 'bool', label: 'allowHttp', help: true },
]

export const CHANNEL_SPECS: Record<string, FieldSpec[]> = {
  smtp: [
    { path: 'host', kind: 'text', label: 'smtpHost', required: true, mono: true },
    { path: 'port', kind: 'number', label: 'smtpPort', help: true },
    {
      path: 'security',
      kind: 'select',
      label: 'smtpSecurity',
      options: ['starttls', 'tls', 'none'],
      default: 'starttls',
    },
    { path: 'allow_insecure', kind: 'bool', label: 'allowInsecure', help: true },
    { path: 'username', kind: 'text', label: 'username' },
    { path: 'password', kind: 'secret', label: 'password' },
    { path: 'from', kind: 'text', label: 'from', required: true },
    { path: 'to', kind: 'list', label: 'to', help: true, required: true },
  ],
  webhook: [...urlFields, { path: 'bearer_token', kind: 'secret', label: 'bearerToken' }],
  slack: urlFields,
  teams: urlFields,
}

function getPath(obj: unknown, path: string): unknown {
  let cur = obj
  for (const key of path.split('.')) {
    if (cur === null || typeof cur !== 'object') return undefined
    cur = (cur as Record<string, unknown>)[key]
  }
  return cur
}

function setPath(obj: Settings, path: string, value: unknown) {
  const keys = path.split('.')
  const last = keys.pop() ?? path
  let cur = obj
  for (const key of keys) {
    const next = cur[key]
    if (next === null || typeof next !== 'object' || Array.isArray(next)) cur[key] = {}
    cur = cur[key] as Settings
  }
  cur[last] = value
}

function deletePath(obj: Settings, path: string) {
  const keys = path.split('.')
  const last = keys.pop() ?? path
  const chain: Settings[] = [obj]
  for (const key of keys) {
    const next = chain[chain.length - 1]?.[key]
    if (next === null || typeof next !== 'object') return
    chain.push(next as Settings)
  }
  Reflect.deleteProperty(chain[chain.length - 1] ?? obj, last)
  // Drop objects emptied by the deletion (`tls: {}`), innermost first.
  for (let i = chain.length - 1; i > 0; i--) {
    const child = chain[i]
    const parent = chain[i - 1]
    if (child && parent && Object.keys(child).length === 0)
      Reflect.deleteProperty(parent, keys[i - 1] ?? '')
  }
}

export function headersToText(h: unknown): string {
  if (h === null || typeof h !== 'object') return ''
  return Object.entries(h as Record<string, unknown>)
    .map(([k, v]) => `${k}: ${String(v)}`)
    .join('\n')
}

/** Parses `Name: value` lines. Returns the first malformed line when there is one. */
export function parseHeaders(text: string): { headers: Record<string, string>; bad?: string } {
  const headers: Record<string, string> = {}
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (line === '') continue
    const i = line.indexOf(':')
    const name = i > 0 ? line.slice(0, i).trim() : ''
    if (name === '') return { headers, bad: line }
    headers[name] = line.slice(i + 1).trim()
  }
  return { headers }
}

/** The form model for a stored settings document; absent values take the spec default. */
export function modelFromSettings(spec: FieldSpec[], settings: Settings | undefined): Model {
  const model: Model = {}
  for (const f of spec) {
    const v = getPath(settings, f.path)
    switch (f.kind) {
      case 'bool':
        model[f.path] = v === undefined ? Boolean(f.default) : v === true
        break
      case 'number':
        model[f.path] = typeof v === 'number' ? v : (f.default as number | undefined)
        break
      case 'list':
        model[f.path] = Array.isArray(v) ? v.map(String) : []
        break
      case 'headers':
        model[f.path] = headersToText(v)
        break
      case 'secret':
        // A masked value stays out of the input; leaving it empty means "unchanged".
        model[f.path] = v === MASK ? '' : typeof v === 'string' ? v : ''
        break
      default:
        model[f.path] = typeof v === 'string' ? v : ((f.default as string | undefined) ?? '')
    }
  }
  return model
}

export function hasStoredSecret(settings: Settings | undefined, path: string): boolean {
  return getPath(settings, path) === MASK
}

/**
 * Builds the settings document from the form. `base` is the document being edited:
 * keys the form does not know are kept, and an untouched secret keeps its mask so
 * the server fills in the stored value.
 */
export function settingsFromModel(
  spec: FieldSpec[],
  model: Model,
  base: Settings | undefined,
): { settings: Settings; badHeaders?: string } {
  // JSON, not structuredClone: `base` is often a reactive proxy, which structuredClone refuses.
  const out = JSON.parse(JSON.stringify(base ?? {})) as Settings
  let badHeaders: string | undefined
  for (const f of spec) {
    const v = model[f.path]
    let value: unknown
    switch (f.kind) {
      case 'bool':
        value = v === true ? true : undefined
        break
      case 'number':
        value = typeof v === 'number' && !Number.isNaN(v) ? v : undefined
        break
      case 'list':
        value = Array.isArray(v) && v.length > 0 ? v : undefined
        break
      case 'headers': {
        const parsed = parseHeaders(typeof v === 'string' ? v : '')
        if (parsed.bad !== undefined) badHeaders ??= parsed.bad
        value = Object.keys(parsed.headers).length > 0 ? parsed.headers : undefined
        break
      }
      case 'secret':
        if (typeof v === 'string' && v !== '') value = v
        else value = hasStoredSecret(base, f.path) ? MASK : undefined
        break
      default:
        value = typeof v === 'string' && v.trim() !== '' ? v.trim() : undefined
    }
    if (value === undefined) deletePath(out, f.path)
    else setPath(out, f.path, value)
  }
  return { settings: out, badHeaders }
}

/** Default settings for a new object of this type. */
export function defaultsFor(spec: FieldSpec[]): Model {
  return modelFromSettings(spec, undefined)
}

/** `Shop SIEM` -> `shop-siem`, the shape the API accepts for an id. */
export function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 63)
}

export const ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}$/

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`
  return `${(n / 1024 / 1024).toFixed(1)} MiB`
}
