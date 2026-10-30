export const PREVIEW_FIELDS = ['Status', 'Title', 'Detail', 'EventID', 'SiteName'] as const
export type PreviewField = (typeof PREVIEW_FIELDS)[number]
export type PreviewValues = Record<PreviewField, string>

export const SAMPLE_VALUES: PreviewValues = {
  Status: '403',
  Title: 'Request blocked',
  Detail: 'This request was blocked by the web application firewall.',
  EventID: 'evt_sample0000',
  SiteName: 'example-site',
}

// Mirrors the data plane's policy so the preview cannot do more than the real page.
const PREVIEW_CSP = "default-src 'none'; style-src 'unsafe-inline'"

export function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

/**
 * Builds the `srcdoc` for the sandboxed preview frame. Only `{{.Field}}` for the known
 * fields is replaced, with HTML-escaped values; the template itself is untrusted and is
 * contained by the iframe sandbox (no scripts, no same-origin) plus the meta CSP.
 */
export function buildPreviewDocument(
  template: string,
  values: PreviewValues = SAMPLE_VALUES,
): string {
  const pattern = new RegExp(`\\{\\{\\s*\\.(${PREVIEW_FIELDS.join('|')})\\s*\\}\\}`, 'g')
  const body = template.replace(pattern, (_match, field: PreviewField) => escapeHtml(values[field]))
  return `<meta http-equiv="Content-Security-Policy" content="${PREVIEW_CSP}">${body}`
}
