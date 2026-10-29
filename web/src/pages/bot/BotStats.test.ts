import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import type { mockClient } from '@/api/testing'
import { ok, problem } from '@/api/testing'
import { adminMe, renderWithApp, viewerMe } from '@/test-utils'

import BotStats from './BotStats.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>
beforeEach(() => Object.values(api).forEach((fn) => fn.mockReset()))

describe('overview bot card', () => {
  it('shows passed and failed challenge counts', async () => {
    api.GET.mockResolvedValue(
      ok({
        dim: 'rule',
        from: '',
        to: '',
        sampled: false,
        items: [
          { value: 'challenge-passed', count: 12 },
          { value: 'challenge-failed', count: 4 },
        ],
      }),
    )
    const { wrapper } = await renderWithApp(BotStats, { me: adminMe })
    expect(wrapper.get('[data-testid="challenge-passed"]').text()).toContain('12')
    expect(wrapper.get('[data-testid="challenge-failed"]').text()).toContain('4')
    expect(api.GET).toHaveBeenCalledWith(
      '/stats/top',
      expect.objectContaining({
        params: { query: expect.objectContaining({ dim: 'rule', limit: 100 }) },
      }),
    )
  })

  it('reports a load failure as an alert', async () => {
    api.GET.mockResolvedValue(problem(500))
    const { wrapper } = await renderWithApp(BotStats, { me: viewerMe })
    expect(wrapper.get('[role="alert"]').text()).toContain('could not be loaded')
  })
})
