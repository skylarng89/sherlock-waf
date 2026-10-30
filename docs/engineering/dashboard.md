# Dashboard conventions

Read this before writing any dashboard page. It is the contract between the foundation (M4-T1..T3) and the page authors (M4-T4 onwards). Stack decisions are in ADR-0008; general TypeScript/Vue style is in `coding-standards.md`.

## Directory layout (`web/`)

| Path | Owner | Contents |
| --- | --- | --- |
| `src/api/` | foundation | `schema.d.ts` (generated, never edit), `client.ts`, `errors.ts`, `fieldErrors.ts`, `useApi.ts`, `testing.ts` |
| `src/stores/` | foundation + areas | `session`, `theme`, `toasts`; an area may add `src/stores/<area>.ts` |
| `src/routes/<area>.ts` | one area author | route records and nav items for the area |
| `src/pages/<area>/` | one area author | `XxxPage.vue`, sub-components, `XxxPage.test.ts` |
| `src/components/` | foundation | shared `Sk*` components. Area-specific components live in `src/pages/<area>/` |
| `src/locales/en/<area>.ts` | one area author | that area's English messages |
| `src/layouts/` | foundation | `AppShell`, `AuthLayout` |
| `src/extensions.ts` | foundation | registration API for Enterprise |
| `src/test-utils.ts` | foundation | `renderWithApp`, `freshApp`, `adminMe`, `viewerMe` |

File ownership: one author per area. Do not edit another area's files. The shared files are `src/routes/index.ts`, `src/locales/index.ts`, `src/App.vue`, `src/layouts/*` and `src/components/Sk*`; changing them needs the foundation owner. If a shared component lacks something, ask rather than fork it.

## Adding a page

1. **Locale file.** Fill `src/locales/en/<area>.ts` (already created; keys are addressed as `<area>.<key>`, e.g. `t('sites.title')`). Never edit `src/locales/index.ts` for an existing area.
2. **Page.** `src/pages/<area>/XxxPage.vue`, `<script setup lang="ts">`, first element `SkPageHeader` (it renders the single `h1`).
3. **Route module.** Edit `src/routes/<area>.ts`. Add records for sub-pages (`/sites/:site`, `/sites/:site/endpoints`) to the same `routes` array, each with a lazy component, a unique `name`, and `meta`:

   ```ts
   {
     path: '/sites/:site',
     name: 'site-detail',
     component: () => import('@/pages/sites/SiteDetailPage.vue'),
     meta: { titleKey: 'sites.detailTitle', permission: 'config:read' },
   }
   ```

   `meta.permission` is a permission name from the OpenAPI `x-sherlock-permission` values: `config:read`, `config:write`, `events:read`, `audit:read`, `users:manage`, `tokens:own`, `system:read`. The guard sends users without it to the 403 page; the sidebar hides nav items with the same `permission`. Every write button in a page must still be hidden or disabled with `useSessionStore().can('config:write')`: the server enforces it either way.
4. **Nav item.** Items in the module's `nav` array appear in the sidebar sorted by `order` (overview 10, sites 20, defaults 30, certificates 40, history 50, audit 60, users 70, tokens 80). Only top-level pages get nav items.
5. **Test.** `XxxPage.test.ts` next to the page (see Testing).

Route `meta` keys: `layout` (`'app'` default, `'auth'` for the centred card), `public`, `permission`, `titleKey`, `wide`. The page title (`document.title`) is set from `titleKey`; after each navigation the shell moves focus to the page's `h1`.

## API client

Always go through the generated, typed client. Never call `fetch`/`axios` directly and never hand-write request/response types that the spec already defines.

```ts
import { useApi } from '@/api/useApi'
const { client, call, ifMatch } = useApi()
```

- `client.GET/POST/PUT/PATCH/DELETE(path, init)` is `openapi-fetch`: paths, params and bodies are type-checked against `schema.d.ts`. Relative URLs under `/api/v1`, cookie credentials, and the `X-CSRF-Token` header on every non-GET request are handled for you.
- `call(promise, { toast? })` unwraps a result to `{ data, etag, response }` or throws `ApiError`. It shows a toast (with the `request_id`) for errors a field cannot show, and stays silent for field errors and 401. Pass `{ toast: false }` when the page renders the error itself.
- **401** anywhere outside the sign-in endpoints clears the session and routes to `/login?expired=1&redirect=<current>`; you write no code for it.
- **429** surfaces as `ApiError` with `kind === 'rate_limited'` and `retryAfter` seconds.
- `ApiError`: `kind` (`validation | unauthenticated | forbidden | not_found | conflict | stale | precondition_required | rate_limited | server | network | unknown`), `status`, `type`, `code` (last segment of the problem type), `title`, `detail`, `fieldErrors` (`Record<jsonPointer, string[]>`), `hasFieldErrors`, `requestId`, `retryAfter`. Narrow with `isApiError(e)`, `isStale(e)`.

### ETag / If-Match

Reads of config objects return `etag`. Writes must send it back in `If-Match` (the spec declares the header parameter, so TypeScript requires it). A lost race raises `StaleConfigError` (HTTP 412); a missing header raises kind `precondition_required` (428).

### Worked example: edit a site

```ts
const { client, call, ifMatch } = useApi()
const form = useFormErrors({ known: ['name', 'hosts', 'upstream.url'] })
const toasts = useToastStore()

const site = ref<Site>()
const etag = ref<string>()
const stale = ref(false)

async function load() {
  const res = await call(client.GET('/sites/{site}', { params: { path: { site: id } } }))
  site.value = res.data
  etag.value = res.etag
  stale.value = false
}

async function save() {
  form.clear()
  try {
    const res = await call(
      client.PUT('/sites/{site}', {
        params: { path: { site: id }, header: ifMatch(etag.value as string) },
        body: site.value as Site,
      }),
      { toast: false },
    )
    etag.value = res.etag // the response carries the new version
    toasts.success(t('sites.saved'))
  } catch (e) {
    if (isStale(e)) stale.value = true // show a "changed elsewhere, Reload" banner calling load()
    else if (!form.apply(e)) toasts.error(e) // field errors inline, anything else as a toast
  }
}
```

### Field errors

The server sends `errors: [{ path: "/hosts/0", code, message }]`, where `path` is a JSON pointer into the request body. `useFormErrors()` maps pointers to form field paths:

- **Convention:** split on `/`, unescape `~1`/`~0`, join with `.`. `/hosts/0/name` is `hosts.0.name`, `/upstream/url` is `upstream.url`. Name your form model keys (or the `field` ids you give `errorFor`) after the API's property paths and no mapping is needed.
- If a form model differs, pass `aliases: { '/upstream/url': 'upstreamUrl' }` (pointer or dotted path as key).
- Pass `known` (the paths your form renders). Messages for pointers you did not render come back in `form.unmatched`; show them in a form-level alert so no server message is dropped. Acceptance criterion 4 depends on this.
- Bind in the template: `<SkFormField :error="form.errorFor('name')">`.

## Forms

- Every control sits in `SkFormField` (label, help, error, required marker). Bind the control with the slot props: `<template #default="{ attrs, invalid }"><InputText v-bind="attrs" :invalid="invalid" v-model="..." /></template>`. This wires `id`, `aria-describedby`, `aria-invalid`, `aria-required`.
- A value that may come from a parent policy uses `SkInheritedField` (below), not a bare control.
- Destructive actions use `SkConfirmDialog` (`danger`; add `confirm-text="<site name>"` for delete-type-to-confirm).
- Submit with `<form @submit.prevent="save" novalidate>` and a `type="submit"` button; Enter must work. Disable the submit button while busy. Clear a field's error when the user edits it (`form.clear(path)`).
- Never store credentials, tokens or secrets in `localStorage`/`sessionStorage`. Keep secrets shown once (MFA secret, API token) only in component state.

### Shared components

| Component | Props / slots |
| --- | --- |
| `SkPageHeader` | `title`, `description?`, `breadcrumbs?: {label, to?}[]`; slot `actions`. Renders the page `h1` (`data-page-title`, focused after navigation). Exactly one per page. |
| `SkEmptyState` | `title`, `description?`, `icon?`; default slot for actions. |
| `SkStatusBadge` | `mode?: 'detect' \| 'block' \| 'off'`, `state?: 'ok' \| 'warn' \| 'error'`, `label?`. Icon plus text; `mode` wins over `state`. |
| `SkFormField` | `label`, `help?`, `error?`, `required?`, `id?`; slot `{ attrs, id, invalid }`. |
| `SkConfirmDialog` | `open` (v-model:open), `title`, `message?`, `confirmLabel?`, `cancelLabel?`, `danger?`, `confirmText?` (typed confirmation), `busy?`; emits `confirm`, `cancel`, `update:open`; default slot for extra content. Native `<dialog>`: focus trap, Esc, focus return. Initial focus is Cancel (or the typed input). |
| `SkInheritedField` | see below |
| `SkToaster` | mounted once in `App.vue`; use `useToastStore()` (`success`, `info`, `error`). |

`SkDataTable` was deliberately not created: use OpenVue `DataTable` directly and follow the table checklist below.

### `SkInheritedField`

A row for a policy value that may be inherited (global defaults, then site, then endpoint).

```vue
<SkInheritedField
  v-model="form.rateLimit"
  :inherited="effective.rate_limit"
  source="site"
  :label="t('sites.rateLimit')"
  :error="form.errorFor('rate_limit')"
>
  <template #default="{ attrs, value, update }">
    <InputNumber v-bind="attrs" :model-value="value" @update:model-value="update" />
  </template>
</SkInheritedField>
```

| Prop | Meaning |
| --- | --- |
| `v-model` (`modelValue`) | The **override**. `undefined` means "not overridden"; any other value, including `false`, `0`, `''`, is an explicit override. Serialise `undefined` as an omitted field. |
| `inherited` | The value that applies when not overridden. `undefined` shows "not set". |
| `source` | `'defaults'` (default), `'site'`, `'builtin'`: text "Inherited from global defaults / site / built-in default". |
| `sourceLabel` | Custom, already-translated source text; wins over `source`. |
| `defaultOverride` | Initial override when the toggle is switched on; defaults to a JSON copy of `inherited`. |
| `format` | `(value) => string` for showing the inherited value; default Yes/No for booleans, JSON for objects, `String` otherwise. |
| `label`, `help`, `error`, `required`, `disabled` | As `SkFormField`. |

Behaviour: not overridden shows the greyed inherited value plus its source and an "Override" switch (a labelled checkbox with `role="switch"`, named "Override <label>"). Switching on emits the override and reveals the editor slot (`attrs`, `value`, `update`, `disabled`); switching off emits `undefined`, the editor is removed and the inherited value is shown again. When overridden it states what it overrides ("Overrides site: 100/min"). Source is always text and an icon, never colour alone. If nothing is inherited, switching on shows an empty editor; until the editor emits a value the model stays `undefined`.

## Internationalisation

All user-visible strings go through `useI18n().t`, including `aria-label`s, placeholders and toast text. Keys live in your area's file and are addressed `<area>.<key>`. Shared strings (buttons, status labels, error texts) are in `common.*` and `nav.*`; do not duplicate them. API-provided `detail` text may be shown as-is but never as the only explanation.

## Accessibility checklist (per page)

axe-in-Playwright runs on every page in M4-T10 and fails on serious/critical violations. Before you finish a page:

- One `h1` (via `SkPageHeader`), headings do not skip levels. Content is inside the shell's `main`; do not add landmarks that duplicate `header`/`nav`/`main`.
- Every input has a visible `<label>` (use `SkFormField`); placeholders are never the label. Required fields are marked; errors are linked with `aria-describedby` and `aria-invalid` (`SkFormField` does it).
- Icon-only buttons have an accessible name (`aria-label` or `.sr-only` text). Icons are `aria-hidden="true"`.
- Colour is never the only signal: use `SkStatusBadge` (icon + text) and add text/icons for custom states. Use only token colours (`bg-sk-*`, `text-sk-*`, `border-sk-*`): they are contrast-tested in light and dark. Do not hard-code hex colours.
- Everything works by keyboard in a logical order; no `tabindex` above 0; no keyboard traps; focus is always visible (do not remove outlines). Modals use `SkConfirmDialog` or OpenVue `Dialog` with a title and Esc support.
- Tables: `<caption>` or `aria-label`, header cells with `scope`, sortable headers are buttons with `aria-sort`. Wrap wide tables in a scroll container with `tabindex="0"` and a label.
- Dynamic updates: success/failure uses toasts (`role=status`/`alert`); inline status text uses `role="status"`; loading states announce ("Loading ..."). Do not auto-dismiss errors.
- Respect `prefers-reduced-motion` (global CSS handles transitions; do not add JS animation).
- Target size at least 24x24 CSS px for controls; layouts reflow at 320px width without horizontal scroll.
- Text contrast 4.5:1, UI boundaries 3:1 (guaranteed by tokens in `src/styles/main.css` and enforced by `src/styles/tokens.test.ts`). If you need a new colour pair, add it to the token test.

## Testing

Vitest + `@vue/test-utils` + happy-dom. Tests sit next to the code (`*.test.ts`).

```ts
import { client } from '@/api/client'
import { mockClient, ok, problem } from '@/api/testing'
import { adminMe, renderWithApp } from '@/test-utils'

// Replace only the `client` export; keep unwrap/ApiError/etc. real.
vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>

beforeEach(() => Object.values(api).forEach((fn) => fn.mockReset()))

it('loads sites', async () => {
  api.GET.mockResolvedValueOnce(ok({ items: [] }, { etag: '"v3"' }))
  const { wrapper } = await renderWithApp(SitesPage, { me: adminMe })
  expect(api.GET).toHaveBeenCalledWith('/sites', expect.anything())
})

it('shows server validation next to the field', async () => {
  api.PUT.mockResolvedValueOnce(
    problem(422, { errors: [{ path: '/name', code: 'taken', message: 'Name is taken' }] }),
  )
  // ... submit, then expect the message inside the Name field and aria-invalid="true"
})
```

- `ok(data, { etag })` / `problem(status, body, headers)` build results; `problem(412)` yields a `StaleConfigError` through `call`.
- `renderWithApp(Component, { me?, route?, props?, slots?, router? })` mounts with pinia, i18n, router (real route table, no guards) and OpenVue and unmounts after each test. Use `freshApp()` for a router with the real guards (mock `GET /auth/me` and `/setup/status`).
- Use `vi.waitFor` for router navigations to lazy pages, and fake timers (`vi.useFakeTimers()`) for countdowns; never rely on wall-clock time.
- Test: happy path, server validation error placement, a non-field error toast, permission gating (viewer vs admin), and loading/empty states.
- Charts (ECharts) need a canvas that happy-dom lacks: mock `vue-echarts`.
- `pnpm test`, `pnpm lint` (eslint + vue-tsc + prettier --check) and `pnpm build` must pass.

## Extensions (Enterprise)

`src/extensions.ts` exports `registerRoute`, `registerNavItem`, `registerSettingsPanel` (and `extension*` readers). An enterprise bundle imports them and registers before the app mounts; open-source code never imports enterprise code. Routes need a unique `name` and may set `meta.permission`; nav items use `label` (or `labelKey`), `icon`, `permission`, `order`. Settings panels (`{ id, label, component, permission?, order? }`) are exposed through `extensionSettingsPanels`; the defaults/settings page renders them.

## Content-Security-Policy

The production page must run under `default-src 'self'`:

- No inline `<script>`, no inline event handlers, no `eval`/`new Function` (checked by `src/build/csp.test.ts`, which builds in memory and inspects `index.html` and the CSS). No CDN: fonts and the Tabler icon font are bundled; no analytics, no remote images.
- Do not use `v-html`, `style="..."` string attributes written by hand, or `<style>` blocks injected at runtime outside OpenVue. Dynamic Vue `:style` bindings are allowed (they use the CSSOM, which CSP does not block), but prefer Tailwind classes.
- **Styles.** OpenVue injects its theme as `<style>` elements at runtime. It supports a nonce (`csp: { nonce }` in the OpenVue config); `main.ts` reads it from `<meta name="csp-nonce" content="...">` in `index.html` and ignores an unsubstituted placeholder. Two valid server configurations:
  1. *Current (works today):* `style-src 'self' 'unsafe-inline'` as already set in `internal/webui/webui.go`. `script-src` stays `default-src 'self'` with no `unsafe-inline`, which is what matters for XSS.
  2. *Strict (recommended follow-up for the Go side):* generate a random nonce per request, add `<meta name="csp-nonce" content="NONCE">` to the served `index.html`, and send `style-src 'self' 'nonce-NONCE'` (drop `'unsafe-inline'`). The SPA picks the nonce up automatically; no web change needed.
- Required full header (Go side): `default-src 'self'; style-src 'self' 'unsafe-inline'` (or the nonce form); `img-src 'self' data:` (data: is only needed for bundled small assets); `font-src` falls back to `'self'`; `connect-src` falls back to `'self'` (API is same origin); `frame-ancestors 'none'; base-uri 'self'; form-action 'self'`.
- SPA fallback: `webui.NewHandler` already serves `index.html` for extensionless unknown paths, so history-mode routes (`/sites/abc`) survive a reload. Paths with a file extension that do not exist return 404. `/api/...` must be routed to the API handler before the SPA handler.

## Forbidden

- `v-html` (eslint error), `innerHTML`, `eval`, `new Function`, inline scripts.
- `any`, non-null assertions (`!`) outside tests, `@ts-ignore`/`@ts-expect-error` to silence real type errors, disabling or loosening an eslint rule, skipping or weakening a test.
- Calling `fetch`/`XMLHttpRequest` directly; hand-written API types duplicating `schema.d.ts`; editing `src/api/schema.d.ts` (run `make gen`).
- Credentials, tokens, secrets or PII in `localStorage`/`sessionStorage`/cookies written by JS, in logs, or in URLs. Do not log API responses.
- Hard-coded user-visible strings, hard-coded colours, external URLs (CDN fonts, remote icons, images).
- Editing another area's files, or the shared files listed above, without agreement.
- New dependencies without a one-line justification in the PR description.
- Any `git add/commit/push/merge` by an agent (the human runs git).

## Browser end-to-end and accessibility suite (M4-T10)

Playwright specs live in `web/e2e/`. Run them with `make e2e-ui` or `pnpm --dir web e2e` (`pnpm e2e --grep @smoke` for the quick subset; the setup-wizard flow is tagged `@flow @slow`). Chromium must be installed (`pnpm exec playwright install chromium`); nothing is downloaded at test time.

The global setup rebuilds `internal/webui/dist` when sources are newer (`E2E_SKIP_BUILD=1` skips), builds the Go binary into a temporary directory and starts two nodes on random free ports with fresh data dirs, plus a tiny local upstream that answers `origin`. The `flow` node is untouched and used only by the setup-wizard test; the `main` node is bootstrapped through the API (admin, MFA, one site) and its session is shared by the other specs. `E2E_KEEP=1` keeps the temp dir. TOTP codes are computed in the test with an independent RFC 6238 implementation and a strictly increasing step per secret (the server rejects replays).

Because the wizard cannot set `global.admin.listen` (default fixed `127.0.0.1:9444`), each node is seeded with `sherlock config import` of a config with `admin.listen: 127.0.0.1:0` and one placeholder site (a config needs at least one site). Specs: setup flow, axe on every page in both themes, keyboard, CSP and network isolation, field-level errors, viewer role, session expiry. Serious or critical axe violations fail; moderate ones are attached to the report. API responses carry `default-src 'none'`, the SPA `default-src 'self'`.
