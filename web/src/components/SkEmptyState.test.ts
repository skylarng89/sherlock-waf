import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import SkEmptyState from './SkEmptyState.vue'

describe('SkEmptyState', () => {
  it('renders title, description and action slot with a decorative icon', () => {
    const wrapper = mount(SkEmptyState, {
      props: { title: 'No sites', description: 'Add your first site', icon: 'ti ti-world' },
      slots: { default: '<button>Add</button>' },
    })
    expect(wrapper.get('h2').text()).toBe('No sites')
    expect(wrapper.text()).toContain('Add your first site')
    expect(wrapper.get('i').attributes('aria-hidden')).toBe('true')
    expect(wrapper.get('button').text()).toBe('Add')
  })

  it('omits optional parts', () => {
    const wrapper = mount(SkEmptyState, { props: { title: 'Empty' } })
    expect(wrapper.find('i').exists()).toBe(false)
    expect(wrapper.find('p').exists()).toBe(false)
  })
})
