import { describe, expect, it } from 'vitest'
import {
  ALERT_PARAM_SPECS,
  CHANNEL_SPECS,
  EXPORTER_SPECS,
  MASK,
  defaultsFor,
  headersToText,
  modelFromSettings,
  parseHeaders,
  settingsFromModel,
  slugify,
} from './spec'

const webhook = EXPORTER_SPECS.webhook!
const syslog = EXPORTER_SPECS.syslog!

describe('secret masking round-trip', () => {
  const stored = {
    url: MASK,
    hmac_secret: MASK,
    headers: { 'X-Api': MASK },
    allow_http: false,
  }

  it('leaves masked secrets out of the inputs but sends the mask back untouched', () => {
    const model = modelFromSettings(webhook, stored)
    expect(model.url).toBe('')
    expect(model.hmac_secret).toBe('')
    const { settings } = settingsFromModel(webhook, model, stored)
    expect(settings).toEqual({ url: MASK, hmac_secret: MASK, headers: { 'X-Api': MASK } })
  })

  it('sends a retyped secret and keeps the other masked one', () => {
    const model = modelFromSettings(webhook, stored)
    model.hmac_secret = 'n'.repeat(32)
    const { settings } = settingsFromModel(webhook, model, stored)
    expect(settings.hmac_secret).toBe('n'.repeat(32))
    expect(settings.url).toBe(MASK)
  })

  it('omits an empty secret that was never stored', () => {
    const { settings } = settingsFromModel(webhook, defaultsFor(webhook), undefined)
    expect(settings).toEqual({})
  })

  it('keeps header values that still show the mask, so the server fills them in', () => {
    const model = modelFromSettings(webhook, stored)
    expect(model.headers).toBe(`X-Api: ${MASK}`)
    model.headers = `X-Api: ${MASK}\nX-Team: sec`
    expect(settingsFromModel(webhook, model, stored).settings.headers).toEqual({
      'X-Api': MASK,
      'X-Team': 'sec',
    })
  })
})

describe('form to payload', () => {
  it('maps syslog defaults to the documented settings', () => {
    const model = defaultsFor(syslog)
    model.address = ' siem.example.com:6514 '
    expect(settingsFromModel(syslog, model, undefined).settings).toEqual({
      network: 'tcp',
      address: 'siem.example.com:6514',
      format: 'cef',
      facility: 16,
      app_name: 'sherlock',
      framing: 'octet',
    })
  })

  it('nests tls fields and drops the object when both are empty', () => {
    const model = defaultsFor(syslog)
    model['tls.server_name'] = 'siem.example.com'
    expect(settingsFromModel(syslog, model, undefined).settings.tls).toEqual({
      server_name: 'siem.example.com',
    })
    model['tls.server_name'] = ''
    expect(
      settingsFromModel(syslog, model, { tls: { server_name: 'old' } }).settings,
    ).not.toHaveProperty('tls')
  })

  it('keeps settings keys the form does not know', () => {
    const model = defaultsFor(syslog)
    const { settings } = settingsFromModel(syslog, model, { extension_flag: 7 })
    expect(settings.extension_flag).toBe(7)
  })

  it('maps smtp recipients to a list and omits false switches', () => {
    const smtp = CHANNEL_SPECS.smtp!
    const model = defaultsFor(smtp)
    Object.assign(model, {
      host: 'mail.example.com',
      from: 'sherlock@example.com',
      to: ['a@example.com', 'b@example.com'],
    })
    expect(settingsFromModel(smtp, model, undefined).settings).toEqual({
      host: 'mail.example.com',
      security: 'starttls',
      from: 'sherlock@example.com',
      to: ['a@example.com', 'b@example.com'],
    })
  })

  it('maps every alert kind to its params', () => {
    const blocks = ALERT_PARAM_SPECS.blocks_threshold!
    const model = defaultsFor(blocks)
    model.site_id = 'shop'
    expect(settingsFromModel(blocks, model, undefined).settings).toEqual({
      site_id: 'shop',
      threshold: 100,
      window_seconds: 300,
    })
    expect(
      settingsFromModel(
        ALERT_PARAM_SPECS.cert_expiring!,
        defaultsFor(ALERT_PARAM_SPECS.cert_expiring!),
        undefined,
      ).settings,
    ).toEqual({ days: 14 })
    expect(ALERT_PARAM_SPECS.feed_failure).toEqual([])
  })
})

describe('headers', () => {
  it('round-trips and reports a malformed line', () => {
    expect(parseHeaders(headersToText({ A: '1', B: 'x: y' })).headers).toEqual({
      A: '1',
      B: 'x: y',
    })
    expect(parseHeaders('no colon here').bad).toBe('no colon here')
    expect(parseHeaders(': value').bad).toBe(': value')
    expect(parseHeaders('\n\n').headers).toEqual({})
  })
})

describe('slugify', () => {
  it.each([
    ['Corp SIEM', 'corp-siem'],
    ['  --Ops / Slack!! ', 'ops-slack'],
    ['', ''],
  ])('%j -> %j', (input, want) => expect(slugify(input)).toBe(want))
})
