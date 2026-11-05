import { describe, expect, it } from 'vitest'
import { isEmptyDiff, parseDiff } from './diff'

describe('parseDiff', () => {
  it('reads the documented shape', () => {
    const d = parseDiff({
      global: true,
      sites: { added: ['a'], removed: ['b'], changed: [{ site: 'c', fields: ['mode', 'hosts'] }] },
    })
    expect(d).toEqual({
      global: true,
      added: ['a'],
      removed: ['b'],
      changed: [{ site: 'c', fields: ['mode', 'hosts'] }],
    })
  })

  it.each([undefined, null, 'x', 4, [], { sites: 'no' }])('tolerates %j', (input) => {
    expect(isEmptyDiff(parseDiff(input))).toBe(true)
  })

  it('ignores malformed changed entries', () => {
    expect(
      parseDiff({ sites: { changed: [{ fields: ['x'] }, 3, { site: 's' }] } }).changed,
    ).toEqual([{ site: 's', fields: [] }])
  })
})
