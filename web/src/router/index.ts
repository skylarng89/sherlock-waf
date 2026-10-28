import { createRouter, createWebHistory } from 'vue-router'
import PlaceholderPage from '@/pages/PlaceholderPage.vue'

export const router = createRouter({
  history: createWebHistory(),
  routes: [{ path: '/', name: 'placeholder', component: PlaceholderPage }],
})
