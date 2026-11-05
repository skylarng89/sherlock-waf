import type { components } from '@/api/schema'

export type RawEvent = components['schemas']['Event']

export interface Finding {
  ruleId: string
  module: string
  severity: string
  score: number | undefined
  message: string
  matched: string
  target: string
  tags: string[]
}

export interface EventView {
  id: string
  ts: string
  siteId: string
  mode: string
  action: string
  terminatedBy: string
  node: string
  configVersion: string
  request: {
    method: string
    host: string
    path: string
    query: string
    headers: [string, string][]
    body: string
  }
  response: { status: number | undefined; bytes: number | undefined }
  client: {
    ip: string
    country: string
    asn: number | undefined
    reputation: number | undefined
  }
  score: { inbound: number | undefined; outbound: number | undefined }
  timing: { totalMs: number | undefined; wafMs: number | undefined }
  findings: Finding[]
}

const rec = (v: unknown): Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : {}
const str = (v: unknown): string =>
  typeof v === 'string' ? v : typeof v === 'number' ? String(v) : ''
const num = (v: unknown): number | undefined => (typeof v === 'number' ? v : undefined)

/** Header values may be a string or a list; both end up as text. */
function headers(v: unknown): [string, string][] {
  return Object.entries(rec(v)).map(([name, value]) => [
    name,
    Array.isArray(value) ? value.map(str).join(', ') : str(value),
  ])
}

/**
 * A defensive, typed read of an event document. Every value is coerced to a plain string or
 * number so templates can only ever render it as text.
 */
export function toView(e: RawEvent): EventView {
  const request = rec(e.request)
  const response = rec(e.response)
  const client = rec(e.client)
  const score = rec(e.anomaly_score)
  const timing = rec(e.timing)
  const findings = Array.isArray(e.findings) ? e.findings : []
  return {
    id: str(e.id),
    ts: str(e.ts),
    siteId: str(e.site_id),
    mode: str(e.mode),
    action: str(e.action),
    terminatedBy: str(e.terminated_by),
    node: str(e.node),
    configVersion: str(e.config_version),
    request: {
      method: str(request.method),
      host: str(request.host),
      path: str(request.path),
      query: str(request.query),
      headers: headers(request.headers),
      body: str(request.body_excerpt),
    },
    response: { status: num(response.status), bytes: num(response.bytes) },
    client: {
      ip: str(client.ip),
      country: str(client.country),
      asn: num(client.asn),
      reputation: num(client.reputation),
    },
    score: { inbound: num(score.inbound), outbound: num(score.outbound) },
    timing: { totalMs: num(timing.total_ms), wafMs: num(timing.waf_ms) },
    findings: findings.map((f) => {
      const o = rec(f)
      return {
        ruleId: str(o.rule_id),
        module: str(o.module),
        severity: str(o.severity),
        score: num(o.score),
        message: str(o.message),
        matched: str(o.matched),
        target: str(o.target),
        tags: Array.isArray(o.tags) ? o.tags.map(str) : [],
      }
    }),
  }
}

export const ruleIds = (v: EventView): string[] => [
  ...new Set(v.findings.map((f) => f.ruleId).filter(Boolean)),
]
