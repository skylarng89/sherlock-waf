import { mount } from '@vue/test-utils'
import OpenVue from 'openvue/config'
import Aura from '@openvue/themes/aura'
import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createI18n } from 'vue-i18n'
import en from '@/locales/en'
import PlaceholderPage from './PlaceholderPage.vue'

// ECharts needs a real canvas, which happy-dom lacks; the chart is exercised by the build
// here and by browser tests in a later milestone.
vi.mock('vue-echarts', () => ({
  default: { name: 'VChart', template: '<div data-testid="chart" />' },
}))

describe('PlaceholderPage', () => {
  beforeEach(() => {
    localStorage.clear()
    document.documentElement.classList.remove('dark')
    setActivePinia(createPinia())
  })

  function render() {
    return mount(PlaceholderPage, {
      global: {
        plugins: [
          createI18n({ legacy: false, locale: 'en', messages: { en } }),
          [OpenVue, { theme: { preset: Aura } }],
        ],
      },
    })
  }

  it('renders the heading, a button and an icon', () => {
    const wrapper = render()
    expect(wrapper.get('h1').text()).toContain('Sherlock WAF')
    expect(wrapper.findAll('button').length).toBeGreaterThanOrEqual(2)
    expect(wrapper.find('i.ti.ti-shield-check').exists()).toBe(true)
  })

  it('switches to dark mode from the toggle', async () => {
    const wrapper = render()
    await wrapper.get('[data-testid="theme-toggle"]').trigger('click')
    expect(document.documentElement.classList.contains('dark')).toBe(true)
  })
})
