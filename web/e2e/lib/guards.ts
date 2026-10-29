import type { Page } from '@playwright/test'

export interface Observations {
  /** Requests whose origin differs from the application's own. */
  foreignRequests: string[]
  /** App-origin responses with a missing or too-permissive CSP header (see below). */
  missingCsp: string[]
  /** Console errors and CSP violation reports. */
  consoleProblems: string[]
  /** Uncaught exceptions in the page. */
  pageErrors: string[]
}

/** Starts recording what the page loads and logs; read the result after navigating. */
export async function observe(page: Page, appOrigin: string): Promise<Observations> {
  const seen: Observations = {
    foreignRequests: [],
    missingCsp: [],
    consoleProblems: [],
    pageErrors: [],
  }
  await page.addInitScript(() => {
    document.addEventListener('securitypolicyviolation', (e) => {
      console.error(`Content Security Policy violation: ${e.violatedDirective} ${e.blockedURI}`)
    })
  })
  page.on('request', (request) => {
    const url = request.url()
    if (/^(data|blob|about):/.test(url)) return
    if (new URL(url).origin !== appOrigin) seen.foreignRequests.push(`${request.method()} ${url}`)
  })
  page.on('response', (response) => {
    const url = response.url()
    if (!url.startsWith(appOrigin)) return
    const csp = response.headers()['content-security-policy'] ?? ''
    // The SPA and its assets must allow only 'self'; API responses carry the stricter
    // `default-src 'none'`, which is accepted because it grants nothing.
    const isApi = new URL(url).pathname.startsWith('/api/')
    const ok = isApi
      ? /default-src 'none'|default-src 'self'/.test(csp)
      : csp.includes("default-src 'self'")
    if (!ok) {
      seen.missingCsp.push(`${response.status()} ${url} (CSP: ${csp || 'none'})`)
    }
  })
  page.on('console', (msg) => {
    const text = msg.text()
    if (msg.type() === 'error' || text.includes('Content Security Policy')) {
      seen.consoleProblems.push(`${msg.type()}: ${text}`)
    }
  })
  page.on('pageerror', (err) => seen.pageErrors.push(err.message))
  return seen
}
