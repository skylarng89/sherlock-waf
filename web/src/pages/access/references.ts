import { i18n } from '@/i18n'
import type { Policy } from '@/pages/sites/lib/layers'
import { NAME_LIST_FIELDS, type NameList } from './policy'
import type { Config } from './useGlobalConfig'

function names(value: NameList | undefined): string[] {
  if (value === undefined) return []
  return Array.isArray(value) ? value : [...(value.add ?? []), ...(value.remove ?? [])]
}

function used(policy: Policy | undefined): string[] {
  return NAME_LIST_FIELDS.flatMap((f) => names(policy?.acl?.[f]))
}

/**
 * For every IP list name, the places in the stored configuration whose ACL mentions it
 * (global defaults, site policies, endpoint policies), as translated labels.
 */
export function listReferences(config: Config): Map<string, string[]> {
  const t = i18n.global.t
  const out = new Map<string, string[]>()
  const add = (policy: Policy | undefined, where: string) => {
    for (const name of new Set(used(policy))) out.set(name, [...(out.get(name) ?? []), where])
  }
  add(config.global?.defaults, t('access.lists.refs.defaults'))
  for (const site of config.sites) {
    add(site.policy, t('access.lists.refs.site', { site: site.id }))
    for (const ep of site.endpoints ?? []) {
      add(ep.policy, t('access.lists.refs.endpoint', { site: site.id, endpoint: ep.id }))
    }
  }
  return out
}
