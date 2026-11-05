import { describe, expect, it } from 'vitest'
import { qrMatrix } from './qr'

describe('qrMatrix', () => {
  it('picks the smallest version that fits (version 1 is 21x21)', () => {
    expect(qrMatrix('hi')).toHaveLength(21)
  })

  it('grows with the payload and stays square', () => {
    const m = qrMatrix(
      'otpauth://totp/Sherlock:admin?secret=JBSWY3DPEHPK3PXP&issuer=Sherlock+WAF'.repeat(3),
    )
    expect(m.length).toBeGreaterThan(41)
    expect(m.every((row) => row.length === m.length)).toBe(true)
  })

  it('draws the three finder patterns', () => {
    const m = qrMatrix('x')
    for (const [x, y] of [
      [0, 0],
      [14, 0],
      [0, 14],
    ] as const) {
      expect(m[y]?.[x]).toBe(true)
      expect(m[y + 3]?.[x + 3]).toBe(true)
      expect(m[y + 1]?.[x + 1]).toBe(false)
    }
  })

  it('rejects payloads beyond version 40', () => {
    expect(() => qrMatrix('a'.repeat(3000))).toThrow(RangeError)
  })

  it('is deterministic', () => {
    expect(qrMatrix('same')).toEqual(qrMatrix('same'))
  })
})
