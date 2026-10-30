// Shared test helpers for the sites, defaults and setup pages. Import only from *.test.ts.
import type { DOMWrapper, VueWrapper } from '@vue/test-utils'
import type { components } from '@/api/schema'
import { problem, type mockClient } from '@/api/testing'

type Api = ReturnType<typeof mockClient>
type Raw = ReturnType<typeof problem>

export type Site = components['schemas']['Site']

export const blog: Site = {
  id: 'blog',
  hosts: ['blog.example.com'],
  upstreams: { targets: ['10.0.2.1:80'] },
}

/** Index 1 in `[blog, shop]`, so server pointers read `/sites/1/...`. */
export const shop: Site = {
  id: 'shop',
  name: 'Shop',
  hosts: ['shop.example.com'],
  tls: { mode: 'acme', min_version: '1.2', hsts: { enabled: true, max_age: 31536000 } },
  upstreams: { targets: ['10.0.1.10:8080'], lb_policy: 'round_robin' },
  policy: { mode: 'detect', waf: { paranoia_level: 1 } },
  endpoints: [
    {
      id: 'login',
      match: { path: '/login', methods: ['POST'] },
      policy: { waf: { paranoia_level: 2 } },
    },
    { id: 'api', match: { path_prefix: '/api/' } },
    { id: 'api-v2', match: { path_prefix: '/api/v2/' } },
    { id: 'any-login', match: { path: '/login' } },
  ],
}

/** Answers GET requests by path; anything unlisted is a 404. */
export function serve(api: Api, handlers: Record<string, () => Raw>) {
  api.GET.mockImplementation((path: string) =>
    Promise.resolve((handlers[path] ?? (() => problem(404)))()),
  )
}

/** The control wired to the visible label that starts with `label`. */
export function control(wrapper: VueWrapper, label: string) {
  const found = wrapper.findAll('label').find((l) => l.text().startsWith(label))
  if (!found) throw new Error(`no label starting with "${label}"`)
  return wrapper.get(`[id="${found.attributes('for')}"]`)
}

/** The inline error paragraph of the control labelled `label`. */
export function errorOf(wrapper: VueWrapper, label: string): string {
  const id = control(wrapper, label).attributes('id')
  return wrapper.get(`[id="${id}-error"]`).text()
}

export function dialogWithTitle(wrapper: VueWrapper, title: string): DOMWrapper<HTMLDialogElement> {
  const found = wrapper.findAll('dialog').find((d) => d.get('h2').text().includes(title))
  if (!found) throw new Error(`no dialog titled "${title}"`)
  return found as DOMWrapper<HTMLDialogElement>
}

export function buttonNamed(
  wrapper: VueWrapper | DOMWrapper<Element> | Omit<DOMWrapper<Element>, 'exists'>,
  name: string,
) {
  const found = wrapper.findAll('button').find((b) => b.text().includes(name))
  if (!found) throw new Error(`no button "${name}"`)
  return found
}

/** The "Override <label>" switch of a SkInheritedField. */
export function overrideToggle(wrapper: VueWrapper, label: string): DOMWrapper<HTMLInputElement> {
  const found = wrapper
    .findAll('label')
    .find((l) => l.text().includes('Override') && l.text().includes(label))
  if (!found) throw new Error(`no override switch for "${label}"`)
  return found.get('input') as DOMWrapper<HTMLInputElement>
}
