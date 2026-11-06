import type { components } from '@/api/schema'
import { prune } from '@/pages/sites/lib/json'

export type DlpPolicy = components['schemas']['DLPPolicy']
export type DlpPattern = NonNullable<DlpPolicy['custom_patterns']>[number]

export const DLP_ACTIONS = ['mask', 'block', 'log'] as const

export const DLP_DEFAULTS = {
  detect: 'pan',
  action: 'mask',
  max_body_bytes: 1_048_576,
  content_types: 'text/html, text/plain, application/json, application/xml, text/xml',
} as const

export const MIN_BODY = 1024
export const MAX_BODY = 16_777_216
export const MAX_PATTERNS = 20
export const MAX_PATTERN_LENGTH = 512

const NAME = /^[a-z][a-z0-9_]{0,31}$/
const CONTENT_TYPE = /^[a-z0-9][a-z0-9!#$&^_.+-]*(\/[a-z0-9!#$&^_.+*-]*)?$/
/** Constructs Go's RE2 does not support (and so the server would refuse). */
const NOT_RE2 = /\(\?[=!<]|\\[1-9]/

export const CUSTOM = 'custom:'
export const customDetector = (name: string) => `${CUSTOM}${name}`

/** The built-in detectors an operator can switch on or off. */
export const BUILTIN = ['pan', 'iban'] as const

/** The wire form: empty values omitted so the diff against the server is stable. */
export function normaliseDlp(p: DlpPolicy | undefined): DlpPolicy | undefined {
  return prune(p ?? {})
}

/**
 * Keeps `detect` consistent with the declared patterns: a `custom:<name>` entry whose
 * pattern was removed or renamed is dropped, because the server refuses the dangling name.
 */
export function pruneDetect(detect: string[], patterns: DlpPattern[]): string[] {
  const names = new Set(patterns.map((p) => p.name))
  return detect.filter((d) => !d.startsWith(CUSTOM) || names.has(d.slice(CUSTOM.length)))
}

export type FieldErrors = Record<string, string>

/** Client-side mirror of internal/config/dlp.go validation; the server stays authoritative. */
export function validateDlp(p: DlpPolicy | undefined): FieldErrors {
  const errors: FieldErrors = {}
  if (p?.action !== undefined && !(DLP_ACTIONS as readonly string[]).includes(p.action)) {
    errors.action = 'action'
  }
  if (p?.max_body_bytes !== undefined) {
    const n = p.max_body_bytes
    if (!Number.isInteger(n) || n < MIN_BODY || n > MAX_BODY) errors.max_body_bytes = 'bodySize'
  }
  p?.content_types?.forEach((c, i) => {
    if (!CONTENT_TYPE.test(c)) errors[`content_types.${i}`] = 'contentType'
  })
  const patterns = p?.custom_patterns ?? []
  if (patterns.length > MAX_PATTERNS) errors.custom_patterns = 'tooManyPatterns'
  const seen = new Set<string>()
  patterns.forEach((cp, i) => {
    const k = `custom_patterns.${i}`
    if (!NAME.test(cp.name)) errors[`${k}.name`] = 'name'
    else if (seen.has(cp.name)) errors[`${k}.name`] = 'duplicateName'
    seen.add(cp.name)
    if (cp.pattern.trim() === '') errors[`${k}.pattern`] = 'patternRequired'
    else if (cp.pattern.length > MAX_PATTERN_LENGTH) errors[`${k}.pattern`] = 'patternLong'
    else if (NOT_RE2.test(cp.pattern)) errors[`${k}.pattern`] = 'notRe2'
  })
  return errors
}
