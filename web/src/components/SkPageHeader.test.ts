import { describe, expect, it } from 'vitest'
import { renderWithApp } from '@/test-utils'
import SkPageHeader from './SkPageHeader.vue'

describe('SkPageHeader', () => {
  it('renders the title as the page h1 and the description', async () => {
    const { wrapper } = await renderWithApp(SkPageHeader, {
      props: { title: 'Sites', description: 'All protected sites' },
    })
    const h1 = wrapper.get('h1')
    expect(h1.text()).toBe('Sites')
    expect(h1.attributes('tabindex')).toBe('-1')
    expect(wrapper.text()).toContain('All protected sites')
  })

  it('renders the actions slot', async () => {
    const { wrapper } = await renderWithApp(SkPageHeader, {
      props: { title: 'Sites' },
      slots: { actions: '<button>Add site</button>' },
    })
    expect(wrapper.get('button').text()).toBe('Add site')
  })

  it('renders breadcrumbs with the last item as the current page', async () => {
    const { wrapper } = await renderWithApp(SkPageHeader, {
      props: {
        title: 'Edit',
        breadcrumbs: [{ label: 'Sites', to: '/sites' }, { label: 'shop.example.com' }],
      },
    })
    const nav = wrapper.get('nav')
    expect(nav.attributes('aria-label')).toBe('Breadcrumb')
    expect(nav.find('a').attributes('href')).toBe('/sites')
    expect(nav.get('[aria-current="page"]').text()).toBe('shop.example.com')
  })
})
