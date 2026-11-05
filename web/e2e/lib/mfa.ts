import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { currentStep, totpAtStep } from './totp'

/**
 * The server rejects a TOTP step that was already used, but accepts one step ahead of
 * its clock. Each secret therefore gets a strictly increasing step; the poll only
 * waits when two sign-ins would otherwise land on the same 30 s window.
 */
export async function nextTotp(root: string, secret: string): Promise<string> {
  const file = join(root, 'mfa-steps.json')
  const steps: Record<string, number> = existsSync(file)
    ? (JSON.parse(readFileSync(file, 'utf8')) as Record<string, number>)
    : {}
  const candidate = Math.max((steps[secret] ?? -1) + 1, currentStep())
  while (candidate > currentStep() + 1) {
    await new Promise((resolve) => setTimeout(resolve, 500))
  }
  steps[secret] = candidate
  writeFileSync(file, JSON.stringify(steps))
  return totpAtStep(secret, candidate)
}
