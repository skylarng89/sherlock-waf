import { describe, expect, it } from 'vitest'
import { renderWithApp } from '@/test-utils'
import SkStatusBadge from './SkStatusBadge.vue'

describe('SkStatusBadge', () => {
  it.each([
    ['mode', 'detect', 'Detect', 'ti-eye'],
    ['mode', 'block', 'Block', 'ti-shield-lock'],
    ['mode', 'off', 'Off', 'ti-power'],
    ['state', 'ok', 'OK', 'ti-circle-check'],
    ['state', 'warn', 'Warning', 'ti-alert-triangle'],
    ['state', 'error', 'Error', 'ti-circle-x'],
  ])('%s=%s shows text and an icon, never colour alone', async (prop, value, text, icon) => {
    const { wrapper } = await renderWithApp(SkStatusBadge, { props: { [prop]: value } })
    expect(wrapper.text()).toBe(text)
    const i = wrapper.get('i')
    expect(i.classes()).toContain(icon)
    expect(i.attributes('aria-hidden')).toBe('true')
  })

  it('mode takes precedence and label overrides the text', async () => {
    const { wrapper } = await renderWithApp(SkStatusBadge, {
      props: { mode: 'block', state: 'error', label: 'Block (3)' },
    })
    expect(wrapper.text()).toBe('Block (3)')
    expect(wrapper.get('i').classes()).toContain('ti-shield-lock')
  })
})
