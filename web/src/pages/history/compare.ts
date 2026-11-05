import type { components } from '@/api/schema'

type Site = components['schemas']['Site']

export interface CompareRow {
  site: string
  left?: { hosts: string; mode: string }
  right?: { hosts: string; mode: string }
  same: boolean
}

function summarise(s: Site | undefined, noMode: string) {
  return s ? { hosts: s.hosts.join(', '), mode: s.policy?.mode ?? noMode } : undefined
}

/** Side-by-side of site ids, hosts and mode; rows are sorted by site id. */
export function compareSites(left: Site[], right: Site[], noMode: string): CompareRow[] {
  const l = new Map(left.map((s) => [s.id, s]))
  const r = new Map(right.map((s) => [s.id, s]))
  return [...new Set([...l.keys(), ...r.keys()])].sort().map((site) => {
    const a = summarise(l.get(site), noMode)
    const b = summarise(r.get(site), noMode)
    return { site, left: a, right: b, same: !!a && !!b && a.hosts === b.hosts && a.mode === b.mode }
  })
}
