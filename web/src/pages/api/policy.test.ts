import { describe, expect, it } from 'vitest'
import { draftToRule, emptyDraft, normalise, ruleToDraft, totalViolations } from './policy'

describe('jwt rule drafts', () => {
  it('round-trips each key source', () => {
    for (const rule of [
      { jwks_url: 'https://a.example/jwks.json', issuer: 'i' },
      { public_key_pem: '-----BEGIN PUBLIC KEY-----', audiences: ['a', 'b'] },
      { hmac_secret_env: 'JWT_SECRET', issuer: 'i', optional: true, action: 'log' as const },
    ]) {
      const back = draftToRule(ruleToDraft(rule))
      expect(normalise(back as never)).toMatchObject(rule)
    }
  })

  it('splits and normalises list fields', () => {
    const rule = draftToRule({
      ...emptyDraft(),
      key: ' https://a.example/j ',
      paths: '/api/*, /v1/*',
      methods: 'post, put',
      audiences: 'a , b',
    })
    expect(rule.match).toEqual({ paths: ['/api/*', '/v1/*'], methods: ['POST', 'PUT'] })
    expect(rule.jwks_url).toBe('https://a.example/j')
    expect(rule.audiences).toEqual(['a', 'b'])
  })

  it('sends only the chosen key source', () => {
    const rule = draftToRule({ ...emptyDraft(), source: 'hmac_secret_env', key: 'X' })
    expect(rule.jwks_url).toBeUndefined()
    expect(rule.hmac_secret_env).toBe('X')
  })
})

describe('totals', () => {
  it('sums violations', () => {
    expect(totalViolations([{ schema_violations: 2 }, { schema_violations: 3 }])).toBe(5)
    expect(totalViolations([])).toBe(0)
  })
})
