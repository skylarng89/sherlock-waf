import { describe, expect, it } from 'vitest'
import {
  apiQuery,
  emptyFilters,
  fromLocalInput,
  parseFilters,
  toLocalInput,
  toQuery,
} from './filters'

describe('event filters', () => {
  it('parses the URL and drops invalid values', () => {
    const f = parseFilters({
      site: 'shop',
      action: 'nonsense',
      country: 'de',
      status: '99',
      range: 'forever',
      ip: ['1.2.3.4', 'x'],
    })
    expect(f).toMatchObject({
      site: 'shop',
      action: '',
      country: 'DE',
      status: '',
      range: '24h',
      ip: '1.2.3.4',
    })
  })

  it('omits defaults and empty values from the URL', () => {
    expect(toQuery(emptyFilters())).toEqual({})
    expect(toQuery({ ...emptyFilters(), action: 'block', range: '1h', q: '/admin' })).toEqual({
      action: 'block',
      range: '1h',
      q: '/admin',
    })
  })

  it('round-trips through the URL form', () => {
    const f = {
      ...emptyFilters(),
      site: 'a',
      rule_id: '942100',
      status: '403',
      range: '7d' as const,
    }
    expect(parseFilters(toQuery(f))).toEqual(f)
  })

  it('resolves a relative range against now and sends custom bounds as ISO', () => {
    const now = new Date('2026-10-29T12:00:00Z')
    expect(apiQuery({ ...emptyFilters(), range: '1h' }, now).from).toBe('2026-10-29T11:00:00.000Z')
    const custom = apiQuery(
      {
        ...emptyFilters(),
        range: 'custom',
        from: '2026-10-01T00:00:00Z',
        to: '2026-10-02T00:00:00Z',
      },
      now,
    )
    expect(custom).toMatchObject({
      from: '2026-10-01T00:00:00.000Z',
      to: '2026-10-02T00:00:00.000Z',
    })
    expect(apiQuery({ ...emptyFilters(), status: '403' }, now).status).toBe(403)
  })

  it('converts between ISO and datetime-local values', () => {
    const iso = '2026-10-29T12:30:00.000Z'
    expect(fromLocalInput(toLocalInput(iso))).toBe(iso)
    expect(toLocalInput('garbage')).toBe('')
  })
})
