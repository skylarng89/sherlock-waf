import { describe, expect, it } from 'vitest'
import { effectiveAccess } from './effective'
import {
  accessPolicyLists,
  accessPolicyPaths,
  applyNameList,
  buildKey,
  inheritedRateLimits,
  parseKey,
  pruneAccessPolicy,
  resolveNameList,
} from './policy'
import { listReferences } from './references'

const layer = (label: string, policy: object) => ({ label, policy })
const limit = (name: string, n = 1) => ({ name, limit: n, window: '1m' })

describe('name lists', () => {
  it('applies an array as a replacement and {add, remove} as an edit', () => {
    expect(applyNameList(['a', 'b'], ['c'])).toEqual(['c'])
    expect(applyNameList(['a', 'b'], { add: ['c', 'a'], remove: ['b'] })).toEqual(['a', 'c'])
    expect(applyNameList(['a'], undefined)).toEqual(['a'])
  })

  it('resolves the inherited list through the levels, farthest first', () => {
    const resolved = resolveNameList(
      [
        layer('site', { acl: { allow_lists: { add: ['partners'], remove: ['vpn'] } } }),
        layer('global', { acl: { allow_lists: ['office', 'vpn'] } }),
      ],
      'allow_lists',
    )
    expect(resolved).toEqual({ names: ['office', 'partners'], label: 'site' })
    expect(resolveNameList([layer('global', {})], 'deny_lists')).toEqual({
      names: undefined,
      label: undefined,
    })
  })
})

describe('inheritedRateLimits', () => {
  it('unions by name, lets a closer level replace and honours opt-outs', () => {
    const items = inheritedRateLimits([
      layer('site', {
        rate_limits: [limit('login', 5)],
        opt_out: ['rate_limits:legacy'],
      }),
      layer('global', { rate_limits: [limit('global', 600), limit('login', 10), limit('legacy')] }),
    ])
    expect(items.map((i) => [i.item.name, i.item.limit, i.label])).toEqual([
      ['global', 600, 'global'],
      ['login', 5, 'site'],
    ])
  })
})

describe('pruneAccessPolicy', () => {
  it('drops empty values but keeps an empty replacement list', () => {
    expect(
      pruneAccessPolicy({ acl: { allow_lists: [], deny_lists: undefined }, rate_limits: [] }),
    ).toEqual({ acl: { allow_lists: [] } })
    expect(pruneAccessPolicy({ opt_out: [] })).toBeUndefined()
  })
})

describe('field paths', () => {
  it('prefixes every path and covers the per-item fields', () => {
    expect(accessPolicyPaths('policy.')).toContain('policy.rate_limits.3.window')
    expect(accessPolicyLists()).toContain('acl.allow_lists.add')
    expect(accessPolicyLists()).toContain('rate_limits.0.match.paths')
  })
})

describe('effectiveAccess', () => {
  it('maps ACL fields and rate limits to their sources and formats durations', () => {
    const view = effectiveAccess({
      site: 's',
      policy: {
        acl: { allow_lists: ['a'], country_mode: 'deny', countries: [], password_gate: false },
        rate_limits: [limit('x')],
        auto_ban: { enabled: true, window: 300_000_000_000, ban_duration: 7_200_000_000_000 },
      },
      sources: {
        'acl.allow_lists': 'site',
        'acl.countries.mode': 'global',
        'acl.password_gate': 'endpoint:login',
        'rate_limits.x': 'global',
        auto_ban: 'site',
      },
    })
    const byField = Object.fromEntries(view.acl.map((r) => [r.field, r]))
    expect(byField.allow_lists).toMatchObject({ value: 'a', source: 'site' })
    expect(byField.country_mode?.source).toBe('global')
    expect(byField.countries?.value).toBe('-')
    expect(byField.password_gate?.source).toBe('endpoint:login')
    expect(view.rateLimits[0]).toMatchObject({ field: 'x', source: 'global' })
    expect(view.autoBan.map((r) => r.value)).toEqual(['true', '5m', '2h'])
  })
})

describe('listReferences', () => {
  it('finds a list in defaults, sites and endpoints, including add/remove edits', () => {
    const refs = listReferences({
      schema_version: 1,
      global: { defaults: { acl: { deny_lists: ['bad'] } } },
      sites: [
        {
          id: 'shop',
          hosts: ['h'],
          upstreams: { targets: ['t'] },
          policy: { acl: { allow_lists: { remove: ['bad'] } } },
          endpoints: [{ id: 'e', match: { path: '/' }, policy: { acl: { deny_lists: ['bad'] } } }],
        },
      ],
    })
    expect(refs.get('bad')).toEqual(['the global defaults', 'site shop', 'endpoint e of site shop'])
    expect(refs.has('good')).toBe(false)
  })
})

describe('rate limit keys', () => {
  it.each([
    ['ip', 'ip', ''],
    [undefined, 'ip', ''],
    ['header:X-Id', 'header', 'X-Id'],
    ['jwt:client_id', 'jwt', 'client_id'],
    ['api_key:X-Api-Key', 'api_key', 'X-Api-Key'],
    ['mtls_subject', 'mtls_subject', ''],
  ])('round-trips %s', (key, kind, value) => {
    const parsed = parseKey(key)
    expect(parsed).toEqual({ kind, value })
    expect(buildKey(parsed.kind, parsed.value)).toBe(key ?? 'ip')
  })
})
