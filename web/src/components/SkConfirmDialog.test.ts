import { flushPromises } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { renderWithApp } from '@/test-utils'
import SkConfirmDialog from './SkConfirmDialog.vue'

const base = { open: false, title: 'Delete site', message: 'This cannot be undone.' }

async function mountDialog(props: Record<string, unknown> = {}) {
  return renderWithApp(SkConfirmDialog, { props: { ...base, ...props } })
}

describe('SkConfirmDialog', () => {
  it('is closed until opened, then labelled by its title and described by its message', async () => {
    const { wrapper } = await mountDialog()
    const dialog = wrapper.get('dialog').element as HTMLDialogElement
    expect(dialog.open).toBe(false)
    await wrapper.setProps({ open: true })
    expect(dialog.open).toBe(true)
    const el = wrapper.get('dialog')
    expect(el.get(`[id="${el.attributes('aria-labelledby')}"]`).text()).toBe('Delete site')
    expect(el.get(`[id="${el.attributes('aria-describedby')}"]`).text()).toBe(
      'This cannot be undone.',
    )
  })

  it('starts focus on the safe choice (Cancel) and emits confirm', async () => {
    const { wrapper } = await mountDialog({ open: true })
    const buttons = wrapper.findAll('button')
    expect(document.activeElement).toBe(buttons[0]?.element)
    await wrapper.get('form').trigger('submit')
    expect(wrapper.emitted('confirm')).toHaveLength(1)
  })

  it('Esc (native cancel) emits cancel and asks to close', async () => {
    const { wrapper } = await mountDialog({ open: true })
    const event = new Event('cancel', { cancelable: true })
    wrapper.get('dialog').element.dispatchEvent(event)
    expect(event.defaultPrevented).toBe(true)
    expect(wrapper.emitted('cancel')).toHaveLength(1)
    expect(wrapper.emitted('update:open')?.[0]).toEqual([false])
  })

  it('returns focus to the element that opened it', async () => {
    const opener = document.createElement('button')
    document.body.append(opener)
    opener.focus()
    const { wrapper } = await mountDialog()
    await wrapper.setProps({ open: true })
    await flushPromises()
    expect(document.activeElement).not.toBe(opener)
    await wrapper.setProps({ open: false })
    await flushPromises()
    expect(document.activeElement).toBe(opener)
    opener.remove()
  })

  describe('typed confirmation', () => {
    it('keeps Confirm disabled until the exact text is typed, and focuses the input', async () => {
      const { wrapper } = await mountDialog({ open: true, confirmText: 'shop.example.com' })
      const confirm = wrapper.get('button[type="submit"]')
      const input = wrapper.get('input')
      expect(document.activeElement).toBe(input.element)
      expect(wrapper.get('label').text()).toContain('shop.example.com')
      expect(confirm.attributes('disabled')).toBeDefined()

      await input.setValue('shop.example.co')
      expect(confirm.attributes('disabled')).toBeDefined()
      await wrapper.get('form').trigger('submit')
      expect(wrapper.emitted('confirm')).toBeUndefined()

      await input.setValue('shop.example.com')
      expect(confirm.attributes('disabled')).toBeUndefined()
      await wrapper.get('form').trigger('submit')
      expect(wrapper.emitted('confirm')).toHaveLength(1)
    })

    it('resets the typed text each time it opens', async () => {
      const { wrapper } = await mountDialog({ open: true, confirmText: 'x' })
      await wrapper.get('input').setValue('x')
      await wrapper.setProps({ open: false })
      await wrapper.setProps({ open: true })
      expect((wrapper.get('input').element as HTMLInputElement).value).toBe('')
    })
  })

  it('blocks confirm and Esc while busy', async () => {
    const { wrapper } = await mountDialog({ open: true, busy: true })
    expect(wrapper.get('button[type="submit"]').attributes('disabled')).toBeDefined()
    wrapper.get('dialog').element.dispatchEvent(new Event('cancel', { cancelable: true }))
    expect(wrapper.emitted('cancel')).toBeUndefined()
  })
})
