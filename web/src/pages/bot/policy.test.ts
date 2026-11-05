import { describe, expect, it } from 'vitest'
import { challengeCounts, draftToRule, normalise, ruleToDraft, splitList } from './policy'

describe('bot policy helpers', () => {
  it('splits comma lists and drops blanks', () => {
    expect(splitList(' /a, ,/b ,')).toEqual(['/a', '/b'])
  })

  it('round-trips a rule through its draft', () => {
    const rule = {
      match: { paths: ['/login'], methods: ['POST'], countries: ['RU'], reputation: true },
      action: 'block' as const,
    }
    expect(draftToRule(ruleToDraft(rule))).toEqual(rule)
  })

  it('normalises away empty values but keeps an explicit false', () => {
    expect(normalise({ enabled: false, site_key: '', rules: [] })).toEqual({ enabled: false })
    expect(normalise({})).toBeUndefined()
  })

  it('reads the challenge outcome counters from a rule top-N', () => {
    expect(
      challengeCounts([
        { value: '942100', count: 9 },
        { value: 'challenge-passed', count: 7 },
        { value: 'challenge-failed', count: 3 },
      ]),
    ).toEqual({ passed: 7, failed: 3, issued: 10 })
    expect(challengeCounts([])).toEqual({ passed: 0, failed: 0, issued: 0 })
  })
})
