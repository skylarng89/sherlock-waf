import type { components } from '@/api/schema'
import { clone, prune } from './json'
import { policyFields, policyListFields } from '../policyFields'
import type { Policy } from './layers'

export type Site = components['schemas']['Site']
type TLSConfig = components['schemas']['TLSConfig']
type UpstreamsConfig = components['schemas']['UpstreamsConfig']

/** A Site whose nested objects always exist, so templates can bind `site.tls.mode` directly. */
export interface SiteDraft extends Omit<Site, 'tls' | 'upstreams' | 'policy'> {
  tls: Omit<TLSConfig, 'hsts'> & { hsts: NonNullable<TLSConfig['hsts']> }
  upstreams: Omit<UpstreamsConfig, 'health_check' | 'tls' | 'timeouts'> & {
    health_check: NonNullable<UpstreamsConfig['health_check']>
    tls: NonNullable<UpstreamsConfig['tls']>
    timeouts: NonNullable<UpstreamsConfig['timeouts']>
  }
  policy: Policy
}

export const SITE_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}$/

/** Defaults for a new site: safe, observable first (detect mode, ACME, HSTS on). */
export function newSiteDraft(): SiteDraft {
  return hydrate({
    id: '',
    name: '',
    hosts: [],
    tls: {
      mode: 'acme',
      min_version: '1.2',
      hsts: { enabled: true, max_age: 31536000, include_subdomains: false },
    },
    upstreams: {
      targets: [],
      lb_policy: 'round_robin',
      tls: { enabled: false, insecure_skip_verify: false },
      timeouts: { dial: '5s', read: '60s', write: '60s' },
      websockets: true,
    },
    policy: { mode: 'detect' },
  })
}

export function hydrate(site: Site): SiteDraft {
  const copy = clone(site)
  return {
    ...copy,
    tls: { ...copy.tls, hsts: { ...copy.tls?.hsts } },
    upstreams: {
      ...copy.upstreams,
      targets: copy.upstreams?.targets ?? [],
      health_check: { ...copy.upstreams?.health_check },
      tls: { ...copy.upstreams?.tls },
      timeouts: { ...copy.upstreams?.timeouts },
    },
    policy: { ...copy.policy },
  }
}

/** The wire form: empty strings and empty objects are omitted (they mean "default"). */
export function toSite(draft: SiteDraft): Site {
  const pruned = prune(clone(draft)) as Partial<Site> | undefined
  return {
    ...pruned,
    id: draft.id,
    hosts: draft.hosts,
    upstreams: { ...pruned?.upstreams, targets: draft.upstreams.targets },
  }
}

/** Field paths the site form renders; anything else the server reports goes to the summary alert. */
export const siteFieldPaths: string[] = [
  'id',
  'name',
  'hosts',
  'path_prefix',
  'tls.mode',
  'tls.cert_id',
  'tls.min_version',
  'tls.hsts.enabled',
  'tls.hsts.max_age',
  'tls.hsts.include_subdomains',
  'upstreams.targets',
  'upstreams.lb_policy',
  'upstreams.health_check.path',
  'upstreams.health_check.interval',
  'upstreams.health_check.timeout',
  'upstreams.tls.enabled',
  'upstreams.tls.insecure_skip_verify',
  'upstreams.tls.client_cert_id',
  'upstreams.timeouts.dial',
  'upstreams.timeouts.read',
  'upstreams.timeouts.write',
  'upstreams.http_version',
  'upstreams.websockets',
  ...policyFields.map((f) => `policy.${f.path}`),
]

export const siteListFields = [
  'hosts',
  'upstreams.targets',
  ...policyListFields.map((p) => `policy.${p}`),
]
