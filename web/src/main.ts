import OpenVue from 'openvue/config'
import Aura from '@openvue/themes/aura'
import { createPinia } from 'pinia'
import { createApp } from 'vue'
import { createI18n } from 'vue-i18n'
import App from './App.vue'
import en from './locales/en'
import { router } from './router'
import { useThemeStore } from './stores/theme'
import './styles/main.css'

const app = createApp(App)
const pinia = createPinia()

app.use(pinia)
app.use(router)
app.use(createI18n({ legacy: false, locale: 'en', fallbackLocale: 'en', messages: { en } }))
app.use(OpenVue, {
  theme: { preset: Aura, options: { darkModeSelector: '.dark' } },
})

useThemeStore().apply()
app.mount('#app')
