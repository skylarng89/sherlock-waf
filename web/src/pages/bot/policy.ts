import type { components } from '@/api/schema'
import { prune } from '@/pages/sites/lib/json'

export type BotPolicy = components['schemas']['BotPolicy']
export type BotRule = NonNullable<BotPolicy['rules']>[number]

/** A rule as the form edits it: list fields are comma separated text. */
export interface RuleDraft {
  paths: string
  methods: string
  countries: string
  reputation: boolean
  action: 'challenge' | 'block' | 'allow'
}

export const splitList = (text: string): string[] =>
  text
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)

export function ruleToDraft(rule: BotRule): RuleDraft {
  return {
    paths: (rule.match?.paths ?? []).join(', '),
    methods: (rule.match?.methods ?? []).join(', '),
    countries: (rule.match?.countries ?? []).join(', '),
    reputation: rule.match?.reputation === true,
    action: rule.action ?? 'challenge',
  }
}

export function draftToRule(d: RuleDraft): BotRule {
  return {
    match: {
      paths: splitList(d.paths),
      methods: splitList(d.methods).map((m) => m.toUpperCase()),
      countries: splitList(d.countries).map((c) => c.toUpperCase()),
      reputation: d.reputation || undefined,
    },
    action: d.action,
  }
}

/** The wire form of a bot policy: empty values omitted so the diff against the server is stable. */
export function normalise(bot: BotPolicy | undefined): BotPolicy | undefined {
  return prune(bot ?? {})
}

/** Pulls the two challenge outcome counters out of a rule top-N answer. */
export function challengeCounts(items: { value: string; count: number }[]) {
  const count = (id: string) => items.find((i) => i.value === id)?.count ?? 0
  const passed = count('challenge-passed')
  const failed = count('challenge-failed')
  return { passed, failed, issued: passed + failed }
}
