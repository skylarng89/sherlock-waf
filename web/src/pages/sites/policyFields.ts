export type PolicyFieldKind = 'select' | 'number' | 'switch' | 'list' | 'blockpage'

export interface PolicyFieldSpec {
  /** Dotted path in the Policy object; also the form error path. */
  path: string
  kind: PolicyFieldKind
  options?: string[]
  min?: number
  max?: number
}

/** The policy fields this dashboard edits (M1 subset; later milestones add more). */
export const policyFields: PolicyFieldSpec[] = [
  { path: 'mode', kind: 'select', options: ['off', 'detect', 'block'] },
  { path: 'fail_mode', kind: 'select', options: ['open', 'closed'] },
  { path: 'waf.enabled', kind: 'switch' },
  { path: 'waf.paranoia_level', kind: 'number', min: 1, max: 4 },
  { path: 'waf.blocking_paranoia_level', kind: 'number', min: 1, max: 4 },
  { path: 'waf.inbound_threshold', kind: 'number', min: 1 },
  { path: 'waf.outbound_threshold', kind: 'number', min: 1 },
  { path: 'waf.outbound_inspection', kind: 'switch' },
  { path: 'waf.max_body_bytes', kind: 'number', min: 0 },
  { path: 'waf.skip_inspection_extensions', kind: 'list' },
  { path: 'block_page.template_id', kind: 'blockpage' },
]

export const policyListFields = ['waf.skip_inspection_extensions']

/** `waf.paranoia_level` -> `waf_paranoia_level`, the i18n key segment. */
export function fieldKey(path: string): string {
  return path.replaceAll('.', '_')
}
