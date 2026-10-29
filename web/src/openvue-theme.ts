import Aura from '@openvue/themes/aura'
import { definePreset } from '@openvue/themes'

/**
 * Aura with the Sherlock accent (blue-700 on light, blue-400 on dark) so OpenVue
 * buttons match the `--sk-accent` token and keep 4.5:1 label contrast (Aura's default
 * primary, blue-500, gives white text only 3.7:1). The dark selector must match
 * the `.dark` class set by the theme store and the Tailwind `dark` variant.
 */
export const SherlockPreset = definePreset(Aura, {
  semantic: {
    primary: {
      50: '{blue.50}',
      100: '{blue.100}',
      200: '{blue.200}',
      300: '{blue.300}',
      400: '{blue.400}',
      500: '{blue.500}',
      600: '{blue.600}',
      700: '{blue.700}',
      800: '{blue.800}',
      900: '{blue.900}',
      950: '{blue.950}',
    },
    colorScheme: {
      light: {
        primary: {
          color: '{primary.700}',
          contrastColor: '#ffffff',
          hoverColor: '{primary.800}',
          activeColor: '{primary.900}',
        },
      },
      dark: {
        primary: {
          color: '{primary.400}',
          contrastColor: '#0b1220',
          hoverColor: '{primary.300}',
          activeColor: '{primary.200}',
        },
      },
    },
  },
})

export const DARK_MODE_SELECTOR = '.dark'

/** The CSP nonce the server injects into index.html, if any (see docs/engineering/dashboard.md). */
export function readCspNonce(doc: Document = document): string | undefined {
  const value = doc.querySelector<HTMLMetaElement>('meta[name="csp-nonce"]')?.content
  // An un-substituted placeholder means no nonce is in use.
  return value && !value.includes('{') ? value : undefined
}
