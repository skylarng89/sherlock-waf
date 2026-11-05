import { describe, expect, it } from 'vitest'
import { renderWithApp } from '@/test-utils'
import SkInheritedField from './SkInheritedField.vue'

const editor = `<template #default="{ attrs, value, update }">
  <input v-bind="attrs" data-testid="editor" :value="value" @input="update($event.target.value)" />
</template>`

async function mountField(props: Record<string, unknown>) {
  return renderWithApp(SkInheritedField, {
    props: { label: 'Rate limit', ...props },
    slots: { default: editor },
  })
}

describe('SkInheritedField', () => {
  it('shows the inherited value and its source, without an editor, when not overridden', async () => {
    const { wrapper } = await mountField({ inherited: '100/min', source: 'site' })
    expect(wrapper.get('[data-testid="inherited-value"]').text()).toBe('100/min')
    expect(wrapper.text()).toContain('Inherited from site')
    expect(wrapper.find('[data-testid="editor"]').exists()).toBe(false)
    const toggle = wrapper.get('input[type="checkbox"]')
    expect((toggle.element as HTMLInputElement).checked).toBe(false)
    expect(toggle.attributes('role')).toBe('switch')
  })

  it.each([
    ['defaults', 'global defaults'],
    ['site', 'site'],
    ['builtin', 'built-in default'],
  ])('labels the %s source as "%s"', async (source, text) => {
    const { wrapper } = await mountField({ inherited: 1, source })
    expect(wrapper.text()).toContain(`Inherited from ${text}`)
  })

  it('supports a custom source label', async () => {
    const { wrapper } = await mountField({ inherited: 1, sourceLabel: 'endpoint /api' })
    expect(wrapper.text()).toContain('Inherited from endpoint /api')
  })

  it('switching Override on emits a copy of the inherited value', async () => {
    const inherited = { rps: 5 }
    const { wrapper } = await mountField({ inherited })
    await wrapper.get('input[type="checkbox"]').setValue(true)
    const emitted = wrapper.emitted('update:modelValue')?.[0]?.[0]
    expect(emitted).toEqual({ rps: 5 })
    expect(emitted).not.toBe(inherited)
    expect(wrapper.find('[data-testid="editor"]').exists()).toBe(true)
  })

  it('uses defaultOverride instead of the inherited value when given', async () => {
    const { wrapper } = await mountField({ inherited: 100, defaultOverride: 200 })
    await wrapper.get('input[type="checkbox"]').setValue(true)
    expect(wrapper.emitted('update:modelValue')?.[0]).toEqual([200])
  })

  it('switching Override off emits undefined so the field is omitted', async () => {
    const { wrapper } = await mountField({ modelValue: 'x', inherited: 'y' })
    expect(wrapper.find('[data-testid="editor"]').exists()).toBe(true)
    await wrapper.get('input[type="checkbox"]').setValue(false)
    expect(wrapper.emitted('update:modelValue')?.[0]).toEqual([undefined])
    expect(wrapper.find('[data-testid="editor"]').exists()).toBe(false)
  })

  it('treats falsy overrides (false, 0, empty string) as overridden', async () => {
    for (const value of [false, 0, '']) {
      const { wrapper } = await mountField({ modelValue: value, inherited: true })
      expect(wrapper.find('[data-testid="editor"]').exists()).toBe(true)
      expect((wrapper.get('input[type="checkbox"]').element as HTMLInputElement).checked).toBe(true)
    }
  })

  it('shows what is being overridden, and routes editor input to v-model', async () => {
    const { wrapper } = await mountField({
      modelValue: '50/min',
      inherited: '100/min',
      source: 'defaults',
    })
    expect(wrapper.text()).toContain('Overrides global defaults: 100/min')
    await wrapper.get('[data-testid="editor"]').setValue('60/min')
    expect(wrapper.emitted('update:modelValue')?.at(-1)).toEqual(['60/min'])
  })

  it('keeps the editor open when overriding with nothing inherited to copy', async () => {
    const { wrapper } = await mountField({})
    expect(wrapper.get('[data-testid="inherited-value"]').text()).toBe('not set')
    await wrapper.get('input[type="checkbox"]').setValue(true)
    expect(wrapper.find('[data-testid="editor"]').exists()).toBe(true)
  })

  it('formats booleans, objects and custom formatters', async () => {
    expect(
      (await mountField({ inherited: true })).wrapper.get('[data-testid="inherited-value"]').text(),
    ).toBe('Yes')
    expect(
      (await mountField({ inherited: { a: 1 } })).wrapper
        .get('[data-testid="inherited-value"]')
        .text(),
    ).toBe('{"a":1}')
    const custom = await mountField({ inherited: 30, format: (v: number) => `${v} s` })
    expect(custom.wrapper.get('[data-testid="inherited-value"]').text()).toBe('30 s')
  })

  it('follows an external reset of the model back to inherited', async () => {
    const { wrapper } = await mountField({ modelValue: 'x', inherited: 'y' })
    await wrapper.setProps({ modelValue: undefined })
    expect(wrapper.find('[data-testid="editor"]').exists()).toBe(false)
  })

  it('wires label, toggle, errors and aria attributes', async () => {
    const { wrapper } = await mountField({
      modelValue: 'x',
      inherited: 'y',
      error: 'Too high',
      help: 'Per client',
    })
    const editor = wrapper.get('[data-testid="editor"]')
    expect(wrapper.get('label').attributes('for')).toBe(editor.attributes('id'))
    expect(editor.attributes('aria-invalid')).toBe('true')
    expect(editor.attributes('aria-describedby')).toContain('-error')
    expect(wrapper.text()).toContain('Too high')
    // The toggle is named "Override Rate limit" for screen readers.
    const toggleLabel = wrapper.findAll('label')[1]
    expect(toggleLabel?.text()).toContain('Override')
    expect(toggleLabel?.text()).toContain('Rate limit')
  })

  it('does nothing when disabled', async () => {
    const { wrapper } = await mountField({ inherited: 1, disabled: true })
    expect(wrapper.get('input[type="checkbox"]').attributes('disabled')).toBeDefined()
    await wrapper.get('input[type="checkbox"]').trigger('change')
    expect(wrapper.emitted('update:modelValue')).toBeUndefined()
  })
})
