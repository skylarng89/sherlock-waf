import { defineStore } from 'pinia'
import { ref } from 'vue'
import { ApiError } from '@/api/errors'
import { i18n } from '@/i18n'

export type ToastKind = 'error' | 'success' | 'info'

export interface Toast {
  id: number
  kind: ToastKind
  message: string
  /** Shown so users can quote it to support; present for API errors. */
  requestId?: string
}

const AUTO_DISMISS_MS = 6000
let nextId = 1

export const useToastStore = defineStore('toasts', () => {
  const items = ref<Toast[]>([])

  function dismiss(id: number) {
    items.value = items.value.filter((t) => t.id !== id)
  }

  function push(kind: ToastKind, message: string, requestId?: string): number {
    const id = nextId++
    items.value = [...items.value, { id, kind, message, requestId }]
    // Errors persist until dismissed (WCAG 2.2.1); confirmations expire.
    if (kind !== 'error') setTimeout(() => dismiss(id), AUTO_DISMISS_MS)
    return id
  }

  function error(e: unknown): number {
    if (e instanceof ApiError) return push('error', messageFor(e), e.requestId)
    return push('error', i18n.global.t('common.errors.unknown'))
  }

  return {
    items,
    push,
    dismiss,
    error,
    success: (message: string) => push('success', message),
    info: (message: string) => push('info', message),
  }
})

export function messageFor(e: ApiError): string {
  const t = i18n.global.t
  switch (e.kind) {
    case 'network':
      return t('common.errors.network')
    case 'forbidden':
      return t('common.errors.forbidden')
    case 'not_found':
      return t('common.errors.notFound')
    case 'stale':
      return t('common.errors.stale')
    case 'precondition_required':
      return t('common.errors.preconditionRequired')
    case 'rate_limited':
      return t('common.errors.rateLimited', { seconds: e.retryAfter ?? 60 })
    case 'server':
      return t('common.errors.server')
    case 'validation':
    case 'conflict':
      return e.detail ?? e.title
    default:
      return e.detail ?? t('common.errors.unknown')
  }
}
