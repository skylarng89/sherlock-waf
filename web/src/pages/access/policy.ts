import type { components } from '@/api/schema'
import { i18n } from '@/i18n'
import { clone, isObject, prune } from '@/pages/sites/lib/json'
import type { Policy, PolicyLayer } from '@/pages/sites/lib/layers'

export type AclPolicy = components['schemas']['ACLPolicy']
export type NameList = components['schemas']['NameList']
export type RateLimit = components['schemas']['RateLimit']

export type NameListField = 'allow_lists' | 'deny_lists'
export const NAME_LIST_FIELDS: NameListField[] = ['allow_lists', 'deny_lists']

export const OPT_OUT_PREFIX = 'rate_limits:'

/** Mirrors the server rules in internal/config/access_validate.go so the form can say it early. */
export const NAME_PATTERN = /^[a-z0-9][a-z0-9_-]{0,62}$/
export const DURATION_PATTERN = /^(\d+(\.\d+)?(ns|us|µs|ms|s|m|h))+$/
export const COUNTRY_PATTERN = /^[A-Z]{2}$/
export const CLAIM_PATTERN = /^[A-Za-z0-9_.:-]{1,64}$/
export const HEADER_PATTERN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,100}$/
export const MAX_RATE_LIMITS = 50
export const MAX_RATE_LIMIT_VALUE = 1_000_000

export const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] as const

/**
 * `sherlock hash-password` does not exist in the CLI yet. The help text is shown anyway so
 * operators know what the field expects; flip this to false once the command ships.
 */
export const HASH_PASSWORD_CLI_COMING_SOON = false
export const HASH_PASSWORD_COMMAND = 'sherlock hash-password'

export function isNameListEdit(
  value: NameList | undefined,
): value is { add?: string[]; remove?: string[] } {
  return value !== undefined && !Array.isArray(value)
}

export function applyNameList(base: string[], value: NameList | undefined): string[] {
  if (value === undefined) return base
  if (Array.isArray(value)) return [...value]
  const removed = new Set(value.remove ?? [])
  const kept = base.filter((n) => !removed.has(n))
  return [...kept, ...(value.add ?? []).filter((n) => !kept.includes(n))]
}

/** The list a level inherits: parent layers applied from the farthest to the closest. */
export function resolveNameList(
  layers: PolicyLayer[],
  field: NameListField,
): { names: string[] | undefined; label: string | undefined } {
  let names: string[] | undefined
  let label: string | undefined
  for (const layer of [...layers].reverse()) {
    const value = layer.policy?.acl?.[field]
    if (value === undefined) continue
    names = applyNameList(names ?? [], value)
    label = layer.label
  }
  return { names, label }
}

export interface InheritedRateLimit {
  item: RateLimit
  /** Translated name of the level that defines it. */
  label: string
}

export function optOutNames(optOut: string[] | undefined): string[] {
  return (optOut ?? [])
    .filter((o) => o.startsWith(OPT_OUT_PREFIX))
    .map((o) => o.slice(OPT_OUT_PREFIX.length))
}

/** Named items union by name; a closer level replaces an item and opts out of what it inherits. */
export function inheritedRateLimits(layers: PolicyLayer[]): InheritedRateLimit[] {
  let items: InheritedRateLimit[] = []
  for (const layer of [...layers].reverse()) {
    const drop = new Set(optOutNames(layer.policy?.opt_out))
    items = items.filter((i) => !drop.has(i.item.name))
    for (const item of layer.policy?.rate_limits ?? []) {
      const entry = { item, label: layer.label }
      const at = items.findIndex((i) => i.item.name === item.name)
      if (at >= 0) items[at] = entry
      else items.push(entry)
    }
  }
  return items
}

export function rateLimitSummary(rl: RateLimit): string {
  return i18n.global.t('access.rateLimits.summary', {
    limit: rl.limit,
    window: rl.window,
    key: rl.key ?? 'ip',
  })
}

export function matchSummary(rl: RateLimit): string {
  const t = i18n.global.t
  const paths = rl.match?.paths?.length ? rl.match.paths.join(', ') : t('access.rateLimits.anyPath')
  const methods = rl.match?.methods?.length
    ? rl.match.methods.join(', ')
    : t('access.rateLimits.anyMethod')
  return `${paths} · ${methods}`
}

/**
 * The wire form of a policy. Like `prune`, but an empty NameList array is kept: it means
 * "replace the inherited list with nothing", which differs from not overriding.
 */
export function pruneAccessPolicy(policy: Policy): Policy | undefined {
  const pruned: Policy = prune(clone(policy)) ?? {}
  for (const field of NAME_LIST_FIELDS) {
    const value = policy.acl?.[field]
    if (Array.isArray(value) && value.length === 0) {
      pruned.acl = { ...pruned.acl, [field]: [] }
    }
  }
  return Object.keys(pruned).length ? pruned : undefined
}

export function isEmptyObject(value: unknown): boolean {
  return isObject(value) && Object.keys(value).length === 0
}

/** Field paths the access forms render, relative to the policy (`prefix` e.g. `policy.`). */
export function accessPolicyPaths(prefix = ''): string[] {
  const rowFields = [
    'name',
    'limit',
    'window',
    'key',
    'action',
    'match',
    'match.paths',
    'match.methods',
  ]
  const paths = [
    ...NAME_LIST_FIELDS.flatMap((f) => [`acl.${f}`, `acl.${f}.add`, `acl.${f}.remove`]),
    'acl.countries',
    'acl.countries.mode',
    'acl.countries.list',
    'acl.reputation',
    'acl.reputation.enabled',
    'acl.reputation.action',
    'acl.password_gate',
    'acl.password_gate.enabled',
    'acl.password_gate.username',
    'acl.password_gate.password_hash',
    'acl.allow_bypass_waf',
    'rate_limits',
    'opt_out',
    'auto_ban',
    'auto_ban.enabled',
    'auto_ban.blocks_threshold',
    'auto_ban.window',
    'auto_ban.ban_duration',
    ...Array.from({ length: MAX_RATE_LIMITS }, (_, i) =>
      rowFields.map((f) => `rate_limits.${i}.${f}`),
    ).flat(),
  ]
  return paths.map((p) => `${prefix}${p}`)
}

/** Fields rendered as one list control; the server's per-item pointers collapse onto them. */
export function accessPolicyLists(prefix = ''): string[] {
  const lists = [
    ...NAME_LIST_FIELDS.flatMap((f) => [`acl.${f}`, `acl.${f}.add`, `acl.${f}.remove`]),
    'acl.countries.list',
    'opt_out',
    ...Array.from({ length: MAX_RATE_LIMITS }, (_, i) => [
      `rate_limits.${i}.match.paths`,
      `rate_limits.${i}.match.methods`,
    ]).flat(),
  ]
  return lists.map((p) => `${prefix}${p}`)
}

export const KEY_KINDS = ['ip', 'header', 'jwt', 'api_key', 'mtls_subject'] as const
export type KeyKind = (typeof KEY_KINDS)[number]

/** Splits a rate-limit key ("jwt:client_id") into the kind and its argument. */
export function parseKey(key: string | undefined): { kind: KeyKind; value: string } {
  if (key === 'mtls_subject') return { kind: 'mtls_subject', value: '' }
  for (const kind of ['header', 'jwt', 'api_key'] as const) {
    if (key?.startsWith(`${kind}:`)) return { kind, value: key.slice(kind.length + 1) }
  }
  return { kind: 'ip', value: '' }
}

export function buildKey(kind: string, value: string): string {
  if (kind === 'header' || kind === 'jwt' || kind === 'api_key') return `${kind}:${value}`
  return kind === 'mtls_subject' ? 'mtls_subject' : 'ip'
}
