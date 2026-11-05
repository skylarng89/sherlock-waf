import type { components } from '@/api/schema'
import { i18n } from '@/i18n'
import { getAt, isObject } from './json'

export type Policy = components['schemas']['Policy']

export interface PolicyLayer {
  /** Translated name of the level, e.g. "global defaults". */
  label: string
  policy: Policy | undefined
}

export interface Resolved {
  value: unknown
  label: string
}

/** First layer (closest level first) that sets `path`; otherwise the built-in default. */
export function resolveInherited(layers: PolicyLayer[], path: string): Resolved {
  for (const layer of layers) {
    const value = getAt(layer.policy, path)
    if (value !== undefined) return { value, label: layer.label }
  }
  return { value: undefined, label: i18n.global.t('common.inherited.source.builtin') }
}

/** Translates a `sources` value from the effective-policy API. */
export function sourceLabel(source: string | undefined): string {
  const t = i18n.global.t
  if (source === undefined) return t('sites.source.unknown')
  if (source.startsWith('endpoint:')) return t('sites.source.endpoint', { id: source.slice(9) })
  switch (source) {
    case 'default':
      return t('sites.source.default')
    case 'global':
      return t('sites.source.global')
    case 'site':
      return t('sites.source.site')
    case 'derived':
      return t('sites.source.derived')
    default:
      return source
  }
}

/** Flattens a nested policy into dotted leaf paths for display. */
export function flatten(value: unknown, prefix = ''): [string, unknown][] {
  if (isObject(value)) {
    return Object.entries(value).flatMap(([k, v]) => flatten(v, prefix ? `${prefix}.${k}` : k))
  }
  return prefix ? [[prefix, value]] : []
}
