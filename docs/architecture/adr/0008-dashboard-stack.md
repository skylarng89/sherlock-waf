# ADR-0008: Dashboard stack

- Status: Accepted
- Date: 2026-10-28

## Decision

| Concern | Choice | Version at time of writing |
| --- | --- | --- |
| Framework | Vue 3 with `<script setup>` and TypeScript (strict) | 3.5.x stable. Do not adopt 3.6 or Vapor mode until 3.6 is stable |
| Build | Vite | 8.x |
| Components | OpenVue (MIT fork of PrimeVue 4.5.5) | 1.0.x. Same API as PrimeVue, which is the fallback if OpenVue stalls |
| Styling | Tailwind CSS v4 via `@tailwindcss/vite` | 4.x; confirm the release you pin supports Vite 8 |
| Charts | Apache ECharts via `vue-echarts` | 6.x / latest |
| Icons | Tabler Icons webfont (`@tabler/icons-webfont`) | latest |
| State | Pinia | |
| Routing | Vue Router | |
| API client | `openapi-typescript` + `openapi-fetch`, generated from `api/openapi.yaml` | |
| Tests | Vitest (unit), Playwright (e2e) | |
| Lint/format | ESLint (flat config, `eslint-plugin-vue`), Prettier, `vue-tsc --noEmit` | |

The production build is embedded in the Go binary. No CDN or external fonts at runtime (NFR-8): fonts and icons are bundled.

## Consequences

The maintainer's preferred stack, with a large ecosystem and good tooling for Vue 3 + TS. OpenVue is young: wrap its components in thin `Sk*` wrappers only where we customise behaviour, so a switch back to PrimeVue is a dependency change, not a rewrite.
