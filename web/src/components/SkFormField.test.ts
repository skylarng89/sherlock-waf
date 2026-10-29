import { describe, expect, it } from 'vitest'
import { renderWithApp } from '@/test-utils'
import SkFormField from './SkFormField.vue'

const slot = `<template #default="{ attrs }"><input v-bind="attrs" /></template>`

describe('SkFormField', () => {
  it('associates label, help and the control', async () => {
    const { wrapper } = await renderWithApp(SkFormField, {
      props: { label: 'Name', help: 'Shown in the list' },
      slots: { default: slot },
    })
    const input = wrapper.get('input')
    expect(wrapper.get('label').attributes('for')).toBe(input.attributes('id'))
    expect(input.attributes('aria-describedby')).toBe(wrapper.get('p').attributes('id'))
    expect(input.attributes('aria-invalid')).toBeUndefined()
  })

  it('marks the control invalid and describes it by the error', async () => {
    const { wrapper } = await renderWithApp(SkFormField, {
      props: { label: 'Name', help: 'h', error: 'Name is taken' },
      slots: { default: slot },
    })
    const input = wrapper.get('input')
    expect(input.attributes('aria-invalid')).toBe('true')
    const ids = input.attributes('aria-describedby')?.split(' ') ?? []
    expect(ids).toHaveLength(2)
    const error = wrapper.get(`[id="${ids[1]}"]`)
    expect(error.text()).toBe('Name is taken')
    expect(error.attributes('aria-live')).toBe('polite')
  })

  it('exposes required to assistive tech with a visible marker', async () => {
    const { wrapper } = await renderWithApp(SkFormField, {
      props: { label: 'Name', required: true },
      slots: { default: slot },
    })
    expect(wrapper.get('input').attributes('aria-required')).toBe('true')
    expect(wrapper.get('label').text()).toContain('*')
    expect(wrapper.get('label .sr-only').text()).toBe('(required)')
  })

  it('keeps the live region mounted when there is no error yet', async () => {
    const { wrapper } = await renderWithApp(SkFormField, {
      props: { label: 'Name' },
      slots: { default: slot },
    })
    expect(wrapper.find('[aria-live="polite"]').exists()).toBe(true)
    await wrapper.setProps({ error: 'Required' })
    expect(wrapper.get('[aria-live="polite"]').text()).toBe('Required')
  })
})
