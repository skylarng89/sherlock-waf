export interface ChangedSite {
  site: string
  fields: string[]
}

export interface ParsedDiff {
  global: boolean
  added: string[]
  removed: string[]
  changed: ChangedSite[]
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function strings(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []
}

/** Reads the loosely typed `diff` object defensively: an unknown shape yields an empty diff. */
export function parseDiff(diff: unknown): ParsedDiff {
  const out: ParsedDiff = { global: false, added: [], removed: [], changed: [] }
  if (!isRecord(diff)) return out
  const g = diff.global
  out.global = Array.isArray(g)
    ? g.length > 0
    : isRecord(g)
      ? Object.keys(g).length > 0
      : Boolean(g)
  const sites = diff.sites
  if (!isRecord(sites)) return out
  out.added = strings(sites.added)
  out.removed = strings(sites.removed)
  if (Array.isArray(sites.changed)) {
    for (const c of sites.changed) {
      if (isRecord(c) && typeof c.site === 'string') {
        out.changed.push({ site: c.site, fields: strings(c.fields) })
      }
    }
  }
  return out
}

export function isEmptyDiff(d: ParsedDiff): boolean {
  return !d.global && !d.added.length && !d.removed.length && !d.changed.length
}
