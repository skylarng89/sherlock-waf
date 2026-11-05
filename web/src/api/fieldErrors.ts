import { computed, ref } from 'vue'
import { ApiError } from './errors'

/**
 * Convention: a server JSON pointer maps to a dotted form path by splitting on `/`
 * and unescaping `~1` and `~0`. `/hosts/0/name` becomes `hosts.0.name`. Form models
 * whose keys differ from the API (camelCase vs snake_case, flattened fields) pass an
 * `aliases` map from pointer (or dotted path) to the form field path.
 */
export function pointerToPath(pointer: string): string {
  return pointer
    .split('/')
    .slice(1)
    .map((s) => s.replaceAll('~1', '/').replaceAll('~0', '~'))
    .join('.')
}

export interface FieldErrorOptions {
  /** `{ '/upstream/url': 'upstreamUrl' }`; matched against the pointer first, then the dotted path. */
  aliases?: Record<string, string>
}

export interface MappedErrors {
  /** Form field path to the first message for that field. */
  fields: Record<string, string>
  /** Messages for pointers that did not name a registered field (shown as a toast/summary). */
  unmatched: string[]
}

/**
 * Pure mapping of `ApiError.fieldErrors` to per-field messages.
 * `known` is the set of form field paths that render an error; anything else
 * is returned in `unmatched` so no server message is silently dropped.
 */
export function mapFieldErrors(
  error: ApiError,
  known?: readonly string[],
  options: FieldErrorOptions = {},
): MappedErrors {
  const fields: Record<string, string> = {}
  const unmatched: string[] = []
  for (const [pointer, messages] of Object.entries(error.fieldErrors)) {
    const dotted = pointerToPath(pointer)
    const path = options.aliases?.[pointer] ?? options.aliases?.[dotted] ?? dotted
    const message = messages.join(' ')
    if (path !== '' && (!known || known.includes(path))) {
      fields[path] = fields[path] ? `${fields[path]} ${message}` : message
    } else {
      unmatched.push(path ? `${path}: ${message}` : message)
    }
  }
  return { fields, unmatched }
}

/**
 * Form helper. Usage:
 *   const form = useFormErrors({ known: ['name', 'hosts.0'] })
 *   catch (e) { if (!form.apply(e)) throw e }
 *   <SkFormField :error="form.errors.value.name" ...>
 */
export function useFormErrors(options: FieldErrorOptions & { known?: readonly string[] } = {}) {
  const state = ref<Record<string, string>>({})
  const unmatched = ref<string[]>([])

  /** Returns true when the error carried field errors and was applied. */
  function apply(error: unknown): boolean {
    if (!(error instanceof ApiError) || !error.hasFieldErrors) return false
    const mapped = mapFieldErrors(error, options.known, options)
    state.value = mapped.fields
    unmatched.value = mapped.unmatched
    return true
  }

  function clear(path?: string) {
    if (path === undefined) {
      state.value = {}
      unmatched.value = []
    } else if (path in state.value) {
      state.value = Object.fromEntries(Object.entries(state.value).filter(([key]) => key !== path))
    }
  }

  return {
    errors: state,
    unmatched,
    hasErrors: computed(() => Object.keys(state.value).length > 0 || unmatched.value.length > 0),
    errorFor: (path: string): string | undefined => state.value[path],
    apply,
    clear,
  }
}
