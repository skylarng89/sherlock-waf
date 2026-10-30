import { describe, expect, it } from 'vitest'
import { ApiError } from '@/api/errors'
import { useToastStore } from '@/stores/toasts'
import { renderWithApp } from '@/test-utils'
import SkToaster from './SkToaster.vue'

describe('SkToaster', () => {
  it('announces errors with role=alert and shows the request id for support', async () => {
    const { wrapper } = await renderWithApp(SkToaster)
    useToastStore().error(new ApiError({ status: 500, requestId: 'req-42' }))
    await wrapper.vm.$nextTick()
    const alert = wrapper.get('[role="alert"]')
    expect(alert.text()).toContain('Request ID: req-42')
  })

  it('uses role=status for confirmations and dismisses on click', async () => {
    const { wrapper } = await renderWithApp(SkToaster)
    useToastStore().success('Saved')
    await wrapper.vm.$nextTick()
    expect(wrapper.get('[role="status"]').text()).toContain('Saved')
    await wrapper.get('button').trigger('click')
    expect(wrapper.find('[role="status"]').exists()).toBe(false)
  })
})
