import { describe, expect, it } from 'vitest'
import { BASELINE, conflicts, planBaseline } from './fintechBaseline'

type Tree = { [key: string]: Tree }

const status = (plan: ReturnType<typeof planBaseline>, path: string) =>
  plan.rows.find((r) => r.path === path)?.status

describe('Fintech baseline plan', () => {
  it('fills an empty policy and never touches the mode', () => {
    const plan = planBaseline({}, {})
    expect(plan.rows.every((r) => r.status === 'set')).toBe(true)
    expect(plan.patch).toEqual({
      policy: {
        login_protection: {
          enabled: true,
          thresholds: { per_ip: 20, per_username: 5, per_device: 10, window: '10m' },
          action: 'challenge',
        },
        dlp: { enabled: true, detect: ['pan', 'iban'], action: 'mask' },
        bot: { enabled: true, challenge: 'pow' },
      },
    })
    expect(plan.patch).not.toHaveProperty('policy.mode')
  })

  it('is idempotent: applying it twice changes nothing the second time', () => {
    const first = planBaseline({}, {})
    const applied = first.patch?.policy as object
    const second = planBaseline(applied, {})
    expect(second.rows.every((r) => r.status === 'unchanged')).toBe(true)
    expect(second.patch).toBeUndefined()
  })

  it('keeps values the operator set differently unless they opt in', () => {
    const policy = {
      mode: 'block' as const,
      login_protection: { thresholds: { per_ip: 100 }, action: 'block' as const },
      bot: { enabled: true, challenge: 'turnstile' as const },
    }
    const plan = planBaseline(policy, {})
    expect(status(plan, 'login_protection.thresholds.per_ip')).toBe('kept')
    expect(status(plan, 'login_protection.action')).toBe('kept')
    expect(status(plan, 'bot.challenge')).toBe('kept')
    expect(status(plan, 'bot.enabled')).toBe('unchanged')
    expect(status(plan, 'login_protection.thresholds.per_username')).toBe('set')
    const patch = plan.patch?.policy as Tree
    expect(patch.login_protection?.thresholds).not.toHaveProperty('per_ip')
    expect(patch.login_protection).not.toHaveProperty('action')
    expect(patch.bot ?? {}).not.toHaveProperty('challenge')
    expect(conflicts(plan).map((r) => r.path)).toEqual([
      'login_protection.thresholds.per_ip',
      'login_protection.action',
      'bot.challenge',
    ])

    const forced = planBaseline(policy, {}, new Set(['login_protection.thresholds.per_ip']))
    expect(status(forced, 'login_protection.thresholds.per_ip')).toBe('overwrite')
    expect(status(forced, 'login_protection.action')).toBe('kept')
    expect((forced.patch?.policy as Tree).login_protection?.thresholds?.per_ip).toBe(20)
  })

  it('treats a global default as the operator’s choice', () => {
    const plan = planBaseline({}, { dlp: { action: 'block' }, bot: { enabled: true } })
    expect(status(plan, 'dlp.action')).toBe('kept')
    expect(status(plan, 'bot.enabled')).toBe('unchanged')
    const patch = plan.patch?.policy as Tree
    expect(patch.dlp).not.toHaveProperty('action')
    expect(patch).not.toHaveProperty('bot.enabled')
  })

  it('compares durations and detector lists by meaning, not spelling', () => {
    const plan = planBaseline(
      { login_protection: { thresholds: { window: '10m0s' } }, dlp: { detect: ['iban', 'pan'] } },
      {},
    )
    expect(status(plan, 'login_protection.thresholds.window')).toBe('unchanged')
    expect(status(plan, 'dlp.detect')).toBe('unchanged')
  })

  it('says when the mode will not enforce anything and when no login endpoint is declared', () => {
    expect(planBaseline({}, {}).modeHint).toBe(true)
    expect(planBaseline({}, {}).mode).toBe('detect')
    expect(planBaseline({ mode: 'block' }, {}).modeHint).toBe(false)
    expect(planBaseline({}, { mode: 'block' }).modeHint).toBe(false)
    expect(planBaseline({ mode: 'off' }, {}).mode).toBe('off')

    expect(planBaseline({}, {}).needsEndpoints).toBe(true)
    const ep = { path: '/login', username_field: 'email' }
    expect(planBaseline({ login_protection: { endpoints: [ep] } }, {}).needsEndpoints).toBe(false)
    expect(planBaseline({}, { login_protection: { endpoints: [ep] } }).needsEndpoints).toBe(false)
  })

  it('never writes a login endpoint or a mode', () => {
    expect(BASELINE.some((b) => b.path.includes('endpoints') || b.path === 'mode')).toBe(false)
  })
})
