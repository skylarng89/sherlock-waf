import { describe, expect, it } from 'vitest'
import { buildPreviewDocument } from './preview'
import { expiryOf } from './expiry'

const NOW = Date.parse('2026-06-01T00:00:00Z')
const day = (n: number) => new Date(NOW + n * 86_400_000).toISOString()

describe('expiryOf', () => {
  it.each([
    [day(-1), 'expired'],
    [day(0), 'expired'],
    [day(1), 'warning'],
    [day(30), 'warning'],
    [day(31), 'ok'],
    [day(400), 'ok'],
    ['not a date', 'expired'],
  ])('%s is %s', (notAfter, state) => {
    expect(expiryOf(notAfter, NOW).state).toBe(state)
  })

  it('reports whole days left', () => {
    expect(expiryOf(day(12), NOW).days).toBe(12)
  })
})

describe('buildPreviewDocument', () => {
  it('substitutes known fields with escaped values and leaves others alone', () => {
    const doc = buildPreviewDocument('<p>{{.Detail}} {{ .Status }} {{.Other}}</p>', {
      Status: '403',
      Title: 't',
      Detail: '<img src=x onerror=alert(1)>"\'&',
      EventID: 'e',
      SiteName: 's',
    })
    expect(doc).toContain('&lt;img src=x onerror=alert(1)&gt;&quot;&#39;&amp; 403')
    expect(doc).not.toContain('<img src=x')
    expect(doc).toContain('{{.Other}}')
  })
})
