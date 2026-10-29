import { describe, expect, it } from 'vitest'
import { ApiError } from '@/api/errors'
import { getAt, mergePatch, prune, setAt } from './json'
import { rankEndpoints } from './precedence'
import { rebaseFieldErrors } from './rebase'

describe('json helpers', () => {
  it('setAt removes the key and empty parents when set to undefined', () => {
    const policy = { waf: { paranoia_level: 2 }, mode: 'block' }
    expect(setAt(policy, 'waf.paranoia_level', undefined)).toEqual({ mode: 'block' })
    expect(setAt(policy, 'waf.enabled', false)).toEqual({
      waf: { paranoia_level: 2, enabled: false },
      mode: 'block',
    })
    expect(policy.waf.paranoia_level).toBe(2)
    expect(getAt(policy, 'waf.paranoia_level')).toBe(2)
  })

  it('keeps explicit falsy overrides when pruning', () => {
    expect(prune({ a: false, b: 0, c: '', d: {}, e: [], f: { g: '' } })).toEqual({ a: false, b: 0 })
  })

  it('builds a merge patch with null for removed keys', () => {
    expect(
      mergePatch(
        { name: 'a', tls: { mode: 'acme', min_version: '1.2' } },
        { tls: { mode: 'none', min_version: '1.2' } },
      ),
    ).toEqual({
      name: null,
      tls: { mode: 'none' },
    })
    expect(mergePatch({ a: 1 }, { a: 1 })).toBeUndefined()
    expect(mergePatch({ hosts: ['a'] }, { hosts: ['a', 'b'] })).toEqual({ hosts: ['a', 'b'] })
  })
})

describe('rebaseFieldErrors', () => {
  const error = new ApiError({
    status: 422,
    fieldErrors: {
      '/sites/1/hosts/2': ['invalid host'],
      '/sites/1/endpoints/0/match/path': ['must start with /'],
      '/sites/1/policy/mode': ['bad mode'],
      '/global/defaults/waf/paranoia_level': ['too high'],
      '/other': ['kept'],
    },
  })

  it('strips the longest matching document prefix and collapses list items', () => {
    const out = rebaseFieldErrors(error, {
      prefixes: ['/sites/1', '/sites/1/endpoints/0', '/global/defaults'],
      lists: ['hosts'],
    })
    expect(out).toBeInstanceOf(ApiError)
    expect((out as ApiError).fieldErrors).toEqual({
      '/hosts': ['Line 3: invalid host'],
      '/match/path': ['must start with /'],
      '/policy/mode': ['bad mode'],
      '/waf/paranoia_level': ['too high'],
      '/other': ['kept'],
    })
  })

  it('passes other errors through untouched', () => {
    const plain = new Error('x')
    expect(rebaseFieldErrors(plain, { prefixes: [] })).toBe(plain)
  })
})

describe('rankEndpoints', () => {
  it('orders exact > longer prefix > shorter prefix and method-bound before any-method', () => {
    const ranked = rankEndpoints([
      { id: 'short', match: { path_prefix: '/api/' } },
      { id: 'any', match: { path: '/login' } },
      { id: 'long', match: { path_prefix: '/api/v2/' } },
      { id: 'post', match: { path: '/login', methods: ['POST'] } },
    ])
    expect(ranked.map((r) => [r.endpoint.id, r.rank])).toEqual([
      ['post', 1],
      ['any', 2],
      ['long', 3],
      ['short', 4],
    ])
  })

  it('gives equal specificity the same rank', () => {
    const ranked = rankEndpoints([
      { id: 'a', match: { path_prefix: '/aa/' } },
      { id: 'b', match: { path_prefix: '/bb/' } },
    ])
    expect(ranked.map((r) => r.rank)).toEqual([1, 1])
  })
})
