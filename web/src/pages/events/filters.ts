import type { LocationQuery } from 'vue-router'
import type { operations } from '@/api/schema'

export type EventsQuery = NonNullable<operations['listEvents']['parameters']['query']>

export const ACTIONS = ['allow', 'log', 'challenge', 'block', 'ratelimit', 'ban'] as const
export type ActionName = (typeof ACTIONS)[number]

export const RANGES = {
  '15m': 15 * 60_000,
  '1h': 3_600_000,
  '24h': 24 * 3_600_000,
  '7d': 7 * 24 * 3_600_000,
} as const
export type RangeKey = keyof typeof RANGES | 'custom'
export const RANGE_KEYS: RangeKey[] = ['15m', '1h', '24h', '7d', 'custom']
export const DEFAULT_RANGE: RangeKey = '24h'

export interface Filters {
  site: string
  action: '' | ActionName
  rule_id: string
  ip: string
  country: string
  method: string
  status: string
  q: string
  range: RangeKey
  /** ISO timestamps, used only when range is `custom`. */
  from: string
  to: string
}

export const emptyFilters = (): Filters => ({
  site: '',
  action: '',
  rule_id: '',
  ip: '',
  country: '',
  method: '',
  status: '',
  q: '',
  range: DEFAULT_RANGE,
  from: '',
  to: '',
})

const first = (v: LocationQuery[string] | undefined): string => {
  const raw = Array.isArray(v) ? v[0] : v
  return typeof raw === 'string' ? raw.trim() : ''
}
const validDate = (s: string) => s !== '' && !Number.isNaN(new Date(s).getTime())

/** Reads filters from the URL; anything invalid is dropped rather than sent to the API. */
export function parseFilters(query: LocationQuery): Filters {
  const f = emptyFilters()
  f.site = first(query.site)
  const action = first(query.action)
  f.action = (ACTIONS as readonly string[]).includes(action) ? (action as ActionName) : ''
  f.rule_id = first(query.rule_id)
  f.ip = first(query.ip)
  f.country = first(query.country).toUpperCase()
  f.method = first(query.method).toUpperCase()
  const status = first(query.status)
  f.status = /^[1-5]\d\d$/.test(status) ? status : ''
  f.q = first(query.q)
  const range = first(query.range)
  f.range = (RANGE_KEYS as string[]).includes(range) ? (range as RangeKey) : DEFAULT_RANGE
  if (f.range === 'custom') {
    const from = first(query.from)
    const to = first(query.to)
    f.from = validDate(from) ? from : ''
    f.to = validDate(to) ? to : ''
  }
  return f
}

/** The URL form of the filters: defaults and empty values are omitted so URLs stay short. */
export function toQuery(f: Filters): Record<string, string> {
  const q: Record<string, string> = {}
  for (const key of [
    'site',
    'action',
    'rule_id',
    'ip',
    'country',
    'method',
    'status',
    'q',
  ] as const) {
    if (f[key]) q[key] = f[key]
  }
  if (f.range !== DEFAULT_RANGE) q.range = f.range
  if (f.range === 'custom') {
    if (f.from) q.from = f.from
    if (f.to) q.to = f.to
  }
  return q
}

/** The query for GET /events. Relative ranges are resolved against `now` at request time. */
export function apiQuery(f: Filters, now: Date): EventsQuery {
  const out: EventsQuery = {}
  if (f.site) out.site = f.site
  if (f.action) out.action = f.action
  if (f.rule_id) out.rule_id = f.rule_id
  if (f.ip) out.ip = f.ip
  if (f.country) out.country = f.country
  if (f.method) out.method = f.method
  if (f.q) out.q = f.q
  if (f.status) out.status = Number(f.status)
  if (f.range === 'custom') {
    if (f.from) out.from = new Date(f.from).toISOString()
    if (f.to) out.to = new Date(f.to).toISOString()
  } else {
    out.from = new Date(now.getTime() - RANGES[f.range]).toISOString()
  }
  return out
}

const pad = (n: number) => String(n).padStart(2, '0')

/** ISO timestamp to the value of a `datetime-local` input (local time, minutes). */
export function toLocalInput(iso: string): string {
  if (!validDate(iso)) return ''
  const d = new Date(iso)
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
}

export function fromLocalInput(value: string): string {
  return validDate(value) ? new Date(value).toISOString() : ''
}
