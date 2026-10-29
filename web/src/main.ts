import OpenVue from 'openvue/config'
import { createPinia } from 'pinia'
import { createApp } from 'vue'
import App from './App.vue'
import { i18n } from './i18n'
import { DARK_MODE_SELECTOR, SherlockPreset, readCspNonce } from './openvue-theme'
import { createAppRouter } from './router'
import { installSessionExpiry } from './router/guard'
import { useThemeStore } from './stores/theme'
import './styles/main.css'

// Enterprise bundles register routes, nav items and settings panels (src/extensions.ts)
// before this point, from their own entry that imports this module's pieces.

const app = createApp(App)
const pinia = createPinia()
const router = createAppRouter()
const nonce = readCspNonce()

app.use(pinia)
app.use(i18n)
app.use(OpenVue, {
  theme: { preset: SherlockPreset, options: { darkModeSelector: DARK_MODE_SELECTOR } },
  ...(nonce ? { csp: { nonce } } : {}),
})

const theme = useThemeStore()
theme.apply()
theme.watchSystem()
installSessionExpiry(router)

app.use(router)
app.mount('#app')
