import type { components } from '@/api/schema'
import { isObject } from '@/pages/sites/lib/json'
import type { RateLimit } from './policy'

type Effective = components['schemas']['EffectivePolicy']

export interface EffectiveRow {
  field: string
  value: string
  /** Raw `sources` value (`global`, `site`, `endpoint:<id>`, `default`), undefined when unknown. */
  source: string | undefined
}

export interface EffectiveAccess {
  acl: EffectiveRow[]
  rateLimits: (EffectiveRow & { item: RateLimit })[]
  autoBan: EffectiveRow[]
}

/** The effective ACL fields and the `sources` key that says where each came from. */
const ACL_SOURCES: Record<string, string> = {
  allow_lists: 'acl.allow_lists',
  deny_lists: 'acl.deny_lists',
  country_mode: 'acl.countries.mode',
  countries: 'acl.countries.list',
  reputation: 'acl.reputation',
  reputation_action: 'acl.reputation',
  password_gate: 'acl.password_gate',
  password_gate_username: 'acl.password_gate',
  allow_bypass_waf: 'acl.allow_bypass_waf',
}

/** The API serialises Go durations here as nanoseconds. */
function duration(ns: number): string {
  const seconds = ns / 1e9
  if (seconds % 3600 === 0) return `${seconds / 3600}h`
  if (seconds % 60 === 0) return `${seconds / 60}m`
  return `${seconds}s`
}

function show(value: unknown): string {
  if (Array.isArray(value)) return value.length ? value.map(String).join(', ') : '-'
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  return value === '' || value === undefined || value === null ? '-' : String(value)
}

export function effectiveAccess(result: Effective): EffectiveAccess {
  const policy = result.policy
  const acl = isObject(policy.acl) ? policy.acl : {}
  const autoBan = isObject(policy.auto_ban) ? policy.auto_ban : {}
  const limits = Array.isArray(policy.rate_limits) ? (policy.rate_limits as RateLimit[]) : []
  return {
    acl: Object.entries(acl).map(([field, value]) => ({
      field,
      value: show(value),
      source: result.sources[ACL_SOURCES[field] ?? `acl.${field}`],
    })),
    rateLimits: limits.map((item) => ({
      field: item.name,
      value: '',
      item,
      source: result.sources[`rate_limits.${item.name}`],
    })),
    autoBan: Object.entries(autoBan).map(([field, value]) => ({
      field,
      value:
        (field === 'window' || field === 'ban_duration') && typeof value === 'number'
          ? duration(value)
          : show(value),
      source: result.sources.auto_ban,
    })),
  }
}
