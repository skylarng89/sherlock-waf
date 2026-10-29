import { flushPromises } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { defineComponent, h } from 'vue'
import { client } from '@/api/client'
import type { mockClient } from '@/api/testing'
import { ok, problem } from '@/api/testing'
import { adminMe, renderWithApp, viewerMe } from '@/test-utils'
import CustomRulesPage from './CustomRulesPage.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
// CodeMirror needs layout APIs happy-dom lacks; the editor itself is exercised in Playwright.
vi.mock('./SecLangEditor.vue', () => ({
  default: defineComponent({
    props: {
      modelValue: { type: String, default: '' },
      readonly: { type: Boolean, default: false },
      issueLines: { type: Array, default: () => [] },
    },
    emits: ['update:modelValue'],
    setup(props, { emit, expose }) {
      expose({ goToLine: vi.fn() })
      return () =>
        h('textarea', {
          'data-testid': 'editor',
          'data-lines': JSON.stringify(props.issueLines),
          readonly: props.readonly,
          value: props.modelValue,
          onInput: (e: Event) => emit('update:modelValue', (e.target as HTMLTextAreaElement).value),
        })
    },
  }),
}))
const api = client as unknown as ReturnType<typeof mockClient>
beforeEach(() => Object.values(api).forEach((fn) => fn.mockReset()))

const GOOD = 'SecRule ARGS "@rx x" "id:10001,phase:2,deny"'
const BAD = 'SecRule ARGS "@rx x" "id:10002,phase:2,exec:/bin/sh"'

function validation(valid: boolean) {
  return valid
    ? { valid: true, issues: [], rule_ids: [10001] }
    : {
        valid: false,
        rule_ids: [],
        issues: [{ line: 1, code: 'forbidden_action', message: 'exec is not allowed' }],
      }
}

async function mountPage(me = adminMe, rules = '') {
  vi.useFakeTimers()
  api.POST.mockResolvedValue(ok(validation(true)))
  api.GET.mockResolvedValue(
    ok(
      {
        rules,
        rule_ids: [],
        source: rules ? 'site' : 'none',
        reserved_id_range: { min: 10000, max: 99999 },
      },
      { etag: '"c1"' },
    ),
  )
  const r = await renderWithApp(CustomRulesPage, { me, route: '/sites/blog/custom-rules' })
  return r
}

async function type(wrapper: Awaited<ReturnType<typeof mountPage>>['wrapper'], text: string) {
  await wrapper.get('[data-testid="editor"]').setValue(text)
  await vi.advanceTimersByTimeAsync(700)
  await flushPromises()
}

describe('custom rules page', () => {
  it('rejects a malicious rule: shows the line issue and disables save', async () => {
    const { wrapper } = await mountPage()
    api.POST.mockResolvedValue(ok(validation(false)))
    await type(wrapper, BAD)
    expect(api.POST).toHaveBeenCalledWith(
      '/sites/{site}/custom-rules/validate',
      expect.objectContaining({ body: { rules: BAD } }),
    )
    const issues = wrapper.get('[data-testid="issues"]')
    expect(issues.text()).toContain('Line 1')
    expect(issues.text()).toContain('exec is not allowed')
    expect(wrapper.get('[data-testid="editor"]').attributes('data-lines')).toBe('[1]')
    expect(wrapper.get('button[type="submit"]').attributes('disabled')).toBeDefined()
    vi.useRealTimers()
  })

  it('saves valid rules with If-Match', async () => {
    const { wrapper } = await mountPage()
    api.POST.mockResolvedValue(ok(validation(true)))
    api.PUT.mockResolvedValue(ok({}, { etag: '"c2"' }))
    await type(wrapper, GOOD)
    expect(wrapper.get('[data-testid="validation-status"]').text()).toContain('10001')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(api.PUT).toHaveBeenCalledWith(
      '/sites/{site}/custom-rules',
      expect.objectContaining({
        params: { path: { site: 'blog' }, header: { 'If-Match': '"c1"' } },
        body: { rules: GOOD },
      }),
    )
    vi.useRealTimers()
  })

  it('offers a reload on a stale version', async () => {
    const { wrapper } = await mountPage()
    api.POST.mockResolvedValue(ok(validation(true)))
    api.PUT.mockResolvedValue(problem(412))
    await type(wrapper, GOOD)
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(wrapper.text()).toContain('Reload')
    vi.useRealTimers()
  })

  it('is read-only for a viewer', async () => {
    const { wrapper } = await mountPage(viewerMe, GOOD)
    api.POST.mockResolvedValue(ok(validation(true)))
    await flushPromises()
    expect(wrapper.find('button[type="submit"]').exists()).toBe(false)
    expect(wrapper.get('[data-testid="editor"]').attributes('readonly')).toBeDefined()
    vi.useRealTimers()
  })
})
