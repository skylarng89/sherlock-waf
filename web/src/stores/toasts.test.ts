import { createPinia, setActivePinia } from 'pinia'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/api/errors'
import { useToastStore } from './toasts'

describe('toast store', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    setActivePinia(createPinia())
  })
  afterEach(() => vi.useRealTimers())

  it('shows API errors with the request id and keeps them until dismissed', () => {
    const toasts = useToastStore()
    toasts.error(new ApiError({ status: 500, requestId: 'req-9' }))
    vi.advanceTimersByTime(60_000)
    expect(toasts.items).toHaveLength(1)
    expect(toasts.items[0]).toMatchObject({ kind: 'error', requestId: 'req-9' })
    toasts.dismiss(toasts.items[0]?.id as number)
    expect(toasts.items).toHaveLength(0)
  })

  it('auto-dismisses success messages', () => {
    const toasts = useToastStore()
    toasts.success('Saved')
    expect(toasts.items).toHaveLength(1)
    vi.advanceTimersByTime(6001)
    expect(toasts.items).toHaveLength(0)
  })

  it('uses friendly text for stale and throttled errors', () => {
    const toasts = useToastStore()
    toasts.error(new ApiError({ status: 412 }))
    toasts.error(new ApiError({ status: 429, retryAfter: 7 }))
    expect(toasts.items[0]?.message).toMatch(/Reload/)
    expect(toasts.items[1]?.message).toMatch(/7 seconds/)
  })

  it('falls back to a generic message for non-API errors', () => {
    const toasts = useToastStore()
    toasts.error(new Error('boom'))
    expect(toasts.items[0]?.message).toMatch(/unexpected/)
  })
})
