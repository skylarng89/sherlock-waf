import type { components } from '@/api/schema'

export type Endpoint = components['schemas']['Endpoint']

export type MatchKind = 'path' | 'path_prefix' | 'path_glob'

export function matchKindOf(match: Endpoint['match']): MatchKind {
  if (match.path) return 'path'
  if (match.path_glob) return 'path_glob'
  return 'path_prefix'
}

export function matchValueOf(match: Endpoint['match']): string {
  return match.path ?? match.path_glob ?? match.path_prefix ?? ''
}

export interface Ranked {
  endpoint: Endpoint
  /** 1 is the most specific. Equal ranks tie and may not both match one request. */
  rank: number
  kind: MatchKind
  methodBound: boolean
}

function score(e: Endpoint): [number, number, number] {
  const kind = matchKindOf(e.match)
  const pathRank = kind === 'path' ? 1 : 0
  return [pathRank, matchValueOf(e.match).length, e.match.methods?.length ? 1 : 0]
}

/**
 * Mirrors the compiler's order (config-model.md): exact path first, then longer
 * prefix/glob, and for equal paths a method-bound endpoint beats an any-method one.
 */
export function rankEndpoints(endpoints: Endpoint[]): Ranked[] {
  const sorted = endpoints
    .map((endpoint, index) => ({ endpoint, index, s: score(endpoint) }))
    .sort((a, b) => b.s[0] - a.s[0] || b.s[1] - a.s[1] || b.s[2] - a.s[2] || a.index - b.index)
  let rank = 0
  let previous = ''
  return sorted.map(({ endpoint, s }) => {
    const key = s.join(':')
    if (key !== previous) rank += 1
    previous = key
    return {
      endpoint,
      rank,
      kind: matchKindOf(endpoint.match),
      methodBound: Boolean(endpoint.match.methods?.length),
    }
  })
}
