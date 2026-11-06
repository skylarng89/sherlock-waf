import type { components } from '@/api/schema'
import { prune } from '@/pages/sites/lib/json'

export type LoginPolicy = components['schemas']['LoginProtectionPolicy']
export type LoginEndpoint = NonNullable<LoginPolicy['endpoints']>[number]

export const LOGIN_ACTIONS = ['challenge', 'block', 'log'] as const
export const LOGIN_METHODS = ['POST', 'PUT', 'PATCH', 'GET'] as const

/** What applies when a field is not set anywhere (internal/config/login.go). */
export const LOGIN_DEFAULTS = {
  per_ip: 20,
  per_username: 5,
  per_device: 10,
  window: '10m',
  action: 'challenge',
  method: 'POST',
  failure_statuses: '401, 403',
} as const

export const MAX_ENDPOINTS = 20
export const MAX_THRESHOLD = 100_000
export const MAX_USERNAME_FIELD = 128

/** An endpoint as the form edits it: statuses are comma separated text. */
export interface EndpointDraft {
  path: string
  method: string
  usernameField: string
  failureStatuses: string
}

export const splitList = (text: string): string[] =>
  text
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)

export function endpointToDraft(e: LoginEndpoint): EndpointDraft {
  return {
    path: e.path,
    method: e.method ?? '',
    usernameField: e.username_field,
    failureStatuses: (e.failure_statuses ?? []).join(', '),
  }
}

export function draftToEndpoint(d: EndpointDraft): LoginEndpoint {
  const statuses = splitList(d.failureStatuses).map(Number)
  return {
    path: d.path.trim(),
    method: d.method.trim().toUpperCase() || undefined,
    username_field: d.usernameField.trim(),
    failure_statuses: statuses.length ? statuses : undefined,
  }
}

export const emptyEndpoint = (): EndpointDraft => ({
  path: '/login',
  method: '',
  usernameField: '',
  failureStatuses: '',
})

/** The wire form: empty values omitted so the diff against the server is stable. */
export function normaliseLogin(p: LoginPolicy | undefined): LoginPolicy | undefined {
  return prune(p ?? {})
}

/** Seconds in a Go duration such as `10m`, `90s` or `1h30m`; undefined when it is not one. */
export function parseDuration(text: string): number | undefined {
  const s = text.trim()
  if (!/^(\d+(\.\d+)?(h|m|s))+$/.test(s)) return undefined
  const unit: Record<string, number> = { h: 3600, m: 60, s: 1 }
  let total = 0
  for (const m of s.matchAll(/(\d+(?:\.\d+)?)([hms])/g))
    total += Number(m[1]) * (unit[m[2] ?? ''] ?? 0)
  return total
}

export type FieldErrors = Record<string, string>

/**
 * Client-side mirror of internal/config/login.go validation, so mistakes are shown before
 * a round trip. The server stays authoritative. Keys are the field names the form uses
 * (`endpoints.0.path`, `thresholds.per_ip`, ...), values are i18n keys under `login.errors`.
 */
export function validateLogin(
  p: LoginPolicy | undefined,
  endpoints: EndpointDraft[],
  methods: readonly string[],
): FieldErrors {
  const errors: FieldErrors = {}
  if (p?.action !== undefined && !(LOGIN_ACTIONS as readonly string[]).includes(p.action)) {
    errors.action = 'action'
  }
  if (endpoints.length > MAX_ENDPOINTS) errors.endpoints = 'tooManyEndpoints'
  endpoints.forEach((e, i) => {
    const k = `endpoints.${i}`
    if (!e.path.trim().startsWith('/')) errors[`${k}.path`] = 'path'
    const method = e.method.trim().toUpperCase()
    if (method && !methods.includes(method)) errors[`${k}.method`] = 'method'
    const field = e.usernameField.trim()
    if (field === '') errors[`${k}.username_field`] = 'usernameRequired'
    else if (field.length > MAX_USERNAME_FIELD || /[\r\n\0]/.test(field))
      errors[`${k}.username_field`] = 'usernameInvalid'
    const statuses = splitList(e.failureStatuses)
    if (
      statuses.length > 20 ||
      statuses.some((s) => !/^\d+$/.test(s) || Number(s) < 100 || Number(s) > 599)
    ) {
      errors[`${k}.failure_statuses`] = 'statuses'
    }
  })
  const t = p?.thresholds
  for (const key of ['per_ip', 'per_username', 'per_device'] as const) {
    const v = t?.[key]
    if (v !== undefined && (!Number.isInteger(v) || v < 1 || v > MAX_THRESHOLD)) {
      errors[`thresholds.${key}`] = 'threshold'
    }
  }
  if (t?.window !== undefined) {
    const secs = parseDuration(t.window)
    if (secs === undefined || secs < 60 || secs > 86_400) errors['thresholds.window'] = 'window'
  }
  return errors
}
