import { describe, expect, it } from 'vitest'
import {
  draftToEndpoint,
  endpointToDraft,
  LOGIN_METHODS,
  normaliseLogin,
  parseDuration,
  validateLogin,
  type EndpointDraft,
} from './policy'

const good: EndpointDraft = {
  path: '/api/login',
  method: '',
  usernameField: 'email',
  failureStatuses: '',
}
const check = (p: Parameters<typeof validateLogin>[0], eps: EndpointDraft[] = [good]) =>
  validateLogin(p, eps, LOGIN_METHODS)

describe('endpoint drafts', () => {
  it('round-trips and omits what is empty', () => {
    expect(draftToEndpoint(good)).toEqual({
      path: '/api/login',
      method: undefined,
      username_field: 'email',
      failure_statuses: undefined,
    })
    const ep = {
      path: '/l',
      method: 'PUT',
      username_field: '/user/email',
      failure_statuses: [401, 422],
    }
    expect(draftToEndpoint(endpointToDraft(ep))).toEqual(ep)
  })

  it('upper-cases the method and trims every field', () => {
    expect(
      draftToEndpoint({
        path: ' /l ',
        method: ' post ',
        usernameField: ' u ',
        failureStatuses: ' 401 , 403 ',
      }),
    ).toEqual({ path: '/l', method: 'POST', username_field: 'u', failure_statuses: [401, 403] })
  })

  it('prunes an empty policy to nothing so an untouched form sends no patch', () => {
    expect(normaliseLogin({ endpoints: [], thresholds: {}, action: undefined })).toBeUndefined()
  })
})

describe('parseDuration', () => {
  it('reads Go durations', () => {
    expect(parseDuration('10m')).toBe(600)
    expect(parseDuration('1h30m')).toBe(5400)
    expect(parseDuration('90s')).toBe(90)
    expect(parseDuration('10m0s')).toBe(600)
  })
  it('refuses everything else', () => {
    for (const bad of ['', '10', 'm', '1d', '-5m', '10 m', '1m!'])
      expect(parseDuration(bad)).toBeUndefined()
  })
})

describe('login validation mirrors the server', () => {
  it('accepts a normal policy', () => {
    expect(
      check({ thresholds: { per_ip: 20, per_username: 5, window: '10m' }, action: 'challenge' }),
    ).toEqual({})
  })

  it('flags each endpoint field', () => {
    const errors = check({}, [
      { path: 'login', method: 'FETCH', usernameField: '', failureStatuses: '99, abc' },
      { ...good, usernameField: 'x'.repeat(129) },
    ])
    expect(errors).toEqual({
      'endpoints.0.path': 'path',
      'endpoints.0.method': 'method',
      'endpoints.0.username_field': 'usernameRequired',
      'endpoints.0.failure_statuses': 'statuses',
      'endpoints.1.username_field': 'usernameInvalid',
    })
  })

  it('bounds the thresholds, the window and the number of endpoints', () => {
    expect(check({ thresholds: { per_ip: 0 } })).toHaveProperty('thresholds.per_ip')
    expect(check({ thresholds: { per_username: 100_001 } })).toHaveProperty(
      'thresholds.per_username',
    )
    expect(check({ thresholds: { per_device: 1.5 } })).toHaveProperty('thresholds.per_device')
    expect(check({ thresholds: { window: '10s' } })).toHaveProperty('thresholds.window')
    expect(check({ thresholds: { window: '25h' } })).toHaveProperty('thresholds.window')
    expect(check({ thresholds: { window: 'soon' } })).toHaveProperty('thresholds.window')
    expect(
      check(
        {},
        Array.from({ length: 21 }, () => good),
      ),
    ).toHaveProperty('endpoints')
  })
})
