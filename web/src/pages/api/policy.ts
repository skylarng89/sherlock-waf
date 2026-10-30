import type { components } from '@/api/schema'
import { prune } from '@/pages/sites/lib/json'

export type ApiPolicy = components['schemas']['APIPolicy']
export type JwtRule = components['schemas']['JWTRule']

export const splitList = (text: string): string[] =>
  text
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)

export type KeySource = 'jwks_url' | 'public_key_pem' | 'hmac_secret_env'
export const KEY_SOURCES: KeySource[] = ['jwks_url', 'public_key_pem', 'hmac_secret_env']

/** A JWT rule as the form edits it: lists are comma separated text, the key source is one field. */
export interface JwtDraft {
  paths: string
  methods: string
  source: KeySource
  key: string
  issuer: string
  audiences: string
  clockSkew: string
  optional: boolean
  action: 'block' | 'log'
}

export function ruleToDraft(rule: JwtRule): JwtDraft {
  const source: KeySource = rule.public_key_pem
    ? 'public_key_pem'
    : rule.hmac_secret_env
      ? 'hmac_secret_env'
      : 'jwks_url'
  return {
    paths: (rule.match?.paths ?? []).join(', '),
    methods: (rule.match?.methods ?? []).join(', '),
    source,
    key: rule[source] ?? '',
    issuer: rule.issuer ?? '',
    audiences: (rule.audiences ?? []).join(', '),
    clockSkew: rule.clock_skew ?? '',
    optional: rule.optional === true,
    action: rule.action ?? 'block',
  }
}

export function draftToRule(d: JwtDraft): JwtRule {
  return {
    match: { paths: splitList(d.paths), methods: splitList(d.methods).map((m) => m.toUpperCase()) },
    [d.source]: d.key.trim(),
    issuer: d.issuer.trim(),
    audiences: splitList(d.audiences),
    clock_skew: d.clockSkew.trim(),
    optional: d.optional || undefined,
    action: d.action,
  }
}

export function emptyDraft(): JwtDraft {
  return {
    paths: '/*',
    methods: '',
    source: 'jwks_url',
    key: '',
    issuer: '',
    audiences: '',
    clockSkew: '',
    optional: false,
    action: 'block',
  }
}

/** The wire form of an API policy: empty values omitted so the diff against the server is stable. */
export function normalise(api: ApiPolicy | undefined): ApiPolicy | undefined {
  return prune(api ?? {})
}

/** Total violations an endpoint list reports, for the tab badge. */
export function totalViolations(items: { schema_violations: number }[]): number {
  return items.reduce((n, e) => n + e.schema_violations, 0)
}
