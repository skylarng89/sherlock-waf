import { flushPromises } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { renderWithApp } from '@/test-utils'
import SkFormDialog from './SkFormDialog.vue'

const slots = { default: '<label for="n">Name</label><input id="n" />' }

describe('SkFormDialog', () => {
  it('opens modally, is labelled by its title and focuses the first field', async () => {
    const { wrapper } = await renderWithApp(SkFormDialog, {
      props: { open: false, title: 'Add thing' },
      slots,
    })
    const el = wrapper.get('dialog').element as HTMLDialogElement
    expect(el.open).toBe(false)
    await wrapper.setProps({ open: true })
    await flushPromises()
    expect(el.open).toBe(true)
    expect(
      wrapper.get(`[id="${wrapper.get('dialog').attributes('aria-labelledby')}"]`).text(),
    ).toBe('Add thing')
    expect(document.activeElement).toBe(wrapper.get('input').element)
  })

  it('submits through the form and closes on Esc, unless busy', async () => {
    const { wrapper } = await renderWithApp(SkFormDialog, {
      props: { open: true, title: 'Add thing' },
      slots,
    })
    await wrapper.get('form').trigger('submit')
    expect(wrapper.emitted('submit')).toHaveLength(1)

    const esc = new Event('cancel', { cancelable: true })
    wrapper.get('dialog').element.dispatchEvent(esc)
    expect(esc.defaultPrevented).toBe(true)
    expect(wrapper.emitted('update:open')?.[0]).toEqual([false])

    await wrapper.setProps({ busy: true })
    wrapper.get('dialog').element.dispatchEvent(new Event('cancel', { cancelable: true }))
    expect(wrapper.emitted('update:open')).toHaveLength(1)
    expect(wrapper.findAll('button').every((b) => b.attributes('disabled') !== undefined)).toBe(
      true,
    )
  })
})
