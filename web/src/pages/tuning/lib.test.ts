import { describe, expect, it } from 'vitest'
import { effectiveLevels, removalParts, sortedWarnings, type ExclusionProposal } from './lib'

describe('removalParts', () => {
  it('describes rule, tag and target removals as plain strings', () => {
    const parts = removalParts({
      id: 'x',
      remove_rule_ids: ['942100', '942200-942299'],
      remove_tags: ['attack-sqli'],
      remove_targets: [{ rule_ids: ['941100'], target: 'ARGS:q' }],
    })
    expect(parts).toEqual([
      { key: 'ruleIds', params: { ids: '942100, 942200-942299' } },
      { key: 'tags', params: { tags: 'attack-sqli' } },
      { key: 'target', params: { target: 'ARGS:q', rules: '941100' } },
    ])
  })
})

describe('sortedWarnings', () => {
  it('puts critical warnings first without mutating the proposal', () => {
    const p = {
      warnings: [
        { code: 'broad_scope', severity: 'info', message: 'a' },
        { code: 'whole_category', severity: 'critical', message: 'b' },
        { code: 'blocking_evaluation', severity: 'warning', message: 'c' },
      ],
    } as ExclusionProposal
    expect(sortedWarnings(p).map((w) => w.severity)).toEqual(['critical', 'warning', 'info'])
    expect(p.warnings[0]?.severity).toBe('info')
  })
})

describe('effectiveLevels', () => {
  it('falls back from site to defaults to 1, and blocking to detection', () => {
    expect(effectiveLevels(undefined, undefined)).toEqual({ detect: 1, block: 1 })
    expect(effectiveLevels({ waf: { paranoia_level: 3 } }, { waf: { paranoia_level: 2 } })).toEqual(
      { detect: 3, block: 3 },
    )
    expect(
      effectiveLevels({ waf: { blocking_paranoia_level: 1 } }, { waf: { paranoia_level: 2 } }),
    ).toEqual({ detect: 2, block: 1 })
  })
})
