import { describe, expect, it } from 'vitest'
import { normaliseDlp, pruneDetect, validateDlp } from './policy'

describe('DLP policy helpers', () => {
  it('drops a custom detector whose pattern is gone', () => {
    expect(
      pruneDetect(['pan', 'custom:nin', 'custom:gone'], [{ name: 'nin', pattern: 'x+' }]),
    ).toEqual(['pan', 'custom:nin'])
  })

  it('prunes an empty policy to nothing', () => {
    expect(normaliseDlp({ custom_patterns: [], content_types: [] })).toBeUndefined()
  })
})

describe('DLP validation mirrors the server', () => {
  it('accepts a normal policy', () => {
    expect(
      validateDlp({
        detect: ['pan', 'custom:nin'],
        custom_patterns: [{ name: 'nin', pattern: '[A-Z]{2}[0-9]{6}' }],
        action: 'mask',
        content_types: ['application/json', 'text/'],
        max_body_bytes: 2_097_152,
      }),
    ).toEqual({})
  })

  it('checks the body size and content types', () => {
    expect(validateDlp({ max_body_bytes: 10 })).toHaveProperty('max_body_bytes')
    expect(validateDlp({ max_body_bytes: 1 << 30 })).toHaveProperty('max_body_bytes')
    expect(validateDlp({ content_types: ['Not A Type'] })).toHaveProperty('content_types.0')
  })

  it('checks pattern names, duplicates, emptiness, length and RE2 limits', () => {
    const errors = validateDlp({
      custom_patterns: [
        { name: 'Bad Name', pattern: 'x+' },
        { name: 'a', pattern: '' },
        { name: 'a', pattern: 'y+' },
        { name: 'b', pattern: 'z'.repeat(513) },
        { name: 'c', pattern: 'a(?=b)' },
        { name: 'd', pattern: '(a)\\1' },
      ],
    })
    expect(errors).toEqual({
      'custom_patterns.0.name': 'name',
      'custom_patterns.1.pattern': 'patternRequired',
      'custom_patterns.2.name': 'duplicateName',
      'custom_patterns.3.pattern': 'patternLong',
      'custom_patterns.4.pattern': 'notRe2',
      'custom_patterns.5.pattern': 'notRe2',
    })
  })

  it('caps the number of patterns', () => {
    const many = Array.from({ length: 21 }, (_, i) => ({ name: `p${i}`, pattern: `x${i}` }))
    expect(validateDlp({ custom_patterns: many })).toHaveProperty('custom_patterns')
  })
})
