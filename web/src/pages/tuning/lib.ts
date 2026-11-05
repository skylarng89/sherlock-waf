import type { components } from '@/api/schema'

type S = components['schemas']
export type Exclusion = S['Exclusion']
export type ExclusionProposal = S['ExclusionProposal']
export type ParanoiaImpact = S['ParanoiaImpact']
export type CrsRule = S['CrsRule']
export type VirtualPatch = S['VirtualPatch']
export type VirtualPatchSiteState = S['VirtualPatchSiteState']

export const PARANOIA_LEVELS = [1, 2, 3, 4] as const
export const RESERVED_RULE_IDS = { min: 10000, max: 99999 }

/** What an exclusion removes, as plain strings the UI can render as text. */
export function removalParts(ex: Exclusion): { key: string; params: Record<string, string> }[] {
  const parts: { key: string; params: Record<string, string> }[] = []
  if (ex.remove_rule_ids?.length) {
    parts.push({ key: 'ruleIds', params: { ids: ex.remove_rule_ids.join(', ') } })
  }
  if (ex.remove_tags?.length)
    parts.push({ key: 'tags', params: { tags: ex.remove_tags.join(', ') } })
  for (const t of ex.remove_targets ?? []) {
    const rules = [...(t.rule_ids ?? []), ...(t.tags ?? []).map((x) => `tag ${x}`)]
    parts.push({
      key: 'target',
      params: { target: t.target, rules: rules.length ? rules.join(', ') : '*' },
    })
  }
  return parts
}

export const scopePaths = (ex: Exclusion): string[] => ex.match?.paths ?? []
export const scopeMethods = (ex: Exclusion): string[] => ex.match?.methods ?? []

/** Warnings ordered most severe first so the critical ones are read before the rest. */
export function sortedWarnings(p: ExclusionProposal): ExclusionProposal['warnings'] {
  const rank = { critical: 0, warning: 1, info: 2 } as const
  return [...p.warnings].sort((a, b) => rank[a.severity] - rank[b.severity])
}

/** The effective level: the site value, else the defaults, else the built-in 1. */
export function effectiveLevels(
  site: { waf?: { paranoia_level?: number; blocking_paranoia_level?: number } } | undefined,
  defaults: { waf?: { paranoia_level?: number; blocking_paranoia_level?: number } } | undefined,
): { detect: number; block: number } {
  const detect = site?.waf?.paranoia_level ?? defaults?.waf?.paranoia_level ?? 1
  const block =
    site?.waf?.blocking_paranoia_level ?? defaults?.waf?.blocking_paranoia_level ?? detect
  return { detect, block }
}

/** Patch ids the site policy switches off. */
export function patchState(patch: VirtualPatch, site: string): VirtualPatchSiteState | undefined {
  return patch.sites.find((s) => s.site === site)
}

export const CRS_STATE_ICON: Record<string, string> = {
  enforcing: 'ti ti-shield-check',
  detect_only: 'ti ti-eye',
  inactive: 'ti ti-circle-off',
  disabled: 'ti ti-ban',
  partly_excluded: 'ti ti-adjustments',
}
