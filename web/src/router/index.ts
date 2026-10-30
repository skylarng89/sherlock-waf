import { createRouter, createWebHistory, type Router, type RouterHistory } from 'vue-router'
import { bindRouter } from '@/extensions'
import { builtinRoutes } from '@/routes'
import { installGuards } from './guard'

export function createAppRouter(history: RouterHistory = createWebHistory()): Router {
  const router = createRouter({ history, routes: builtinRoutes })
  installGuards(router)
  bindRouter(router)
  return router
}
