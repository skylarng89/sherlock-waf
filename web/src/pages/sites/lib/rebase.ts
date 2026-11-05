import { ApiError } from '@/api/errors'
import { i18n } from '@/i18n'

/**
 * The server reports JSON pointers relative to the whole configuration document
 * (`/sites/1/endpoints/0/match/path`, `/global/defaults/waf/paranoia_level`), while
 * each form edits one object. `rebase` strips the `prefixes` that locate that object
 * (longest match wins) so the remainder equals the form's field path.
 * Pointers that match no prefix are assumed body-relative and kept. A pointer into
 * a list that the form renders as one control (`/hosts/2`) collapses onto the list
 * field and the message is prefixed with the line number.
 */
export function rebaseFieldErrors(
  error: unknown,
  options: { prefixes: string[]; lists?: string[] },
): unknown {
  if (!(error instanceof ApiError) || !error.hasFieldErrors) return error
  const prefixes = [...options.prefixes].sort((a, b) => b.length - a.length)
  const lists = options.lists ?? []
  const fieldErrors: Record<string, string[]> = {}
  for (const [pointer, messages] of Object.entries(error.fieldErrors)) {
    let rebased = pointer
    const prefix = prefixes.find((p) => pointer === p || pointer.startsWith(`${p}/`))
    if (prefix !== undefined) rebased = pointer.slice(prefix.length)
    let out = messages
    const dotted = rebased.split('/').slice(1).join('.')
    for (const list of lists) {
      const match = new RegExp(`^${list.replaceAll('.', '\\.')}\\.(\\d+)(\\.|$)`).exec(dotted)
      if (match) {
        rebased = `/${list.split('.').join('/')}`
        const line = Number(match[1]) + 1
        out = messages.map((m) => i18n.global.t('sites.errors.line', { line, message: m }))
        break
      }
    }
    ;(fieldErrors[rebased] ??= []).push(...out)
  }
  return new ApiError({
    status: error.status,
    type: error.type,
    title: error.title,
    detail: error.detail,
    requestId: error.requestId,
    fieldErrors,
  })
}
