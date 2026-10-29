import { ref } from 'vue'
import { useFormErrors } from '@/api/fieldErrors'
import { isApiError } from '@/api/errors'
import { useToastStore } from '@/stores/toasts'
import { rebaseFieldErrors } from './rebase'

/**
 * Shared error handling for config writes: 412 and 428 raise a banner offering a reload,
 * 422 field errors land on their fields (after rebasing the document pointers), and
 * anything else becomes a toast. A 409 is handed to `onConflict` (the caller knows which
 * field holds the duplicate id).
 */
export function useWriteFlow(options: {
  form: ReturnType<typeof useFormErrors>
  rebase: () => { prefixes: string[]; lists?: string[] }
  onConflict?: () => void
}) {
  const toasts = useToastStore()
  const stale = ref(false)
  const precondition = ref(false)

  function reset() {
    stale.value = false
    precondition.value = false
    options.form.clear()
  }

  /** Returns after routing the error to the right place; never throws for API errors. */
  function handle(e: unknown): void {
    if (!isApiError(e)) throw e
    if (e.kind === 'stale') stale.value = true
    else if (e.kind === 'precondition_required') precondition.value = true
    else if (e.kind === 'conflict' && options.onConflict) options.onConflict()
    else if (!options.form.apply(rebaseFieldErrors(e, options.rebase()))) toasts.error(e)
  }

  return { stale, precondition, reset, handle }
}
