import { i18n } from '@/i18n'

const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ['day', 86_400],
  ['hour', 3_600],
  ['minute', 60],
  ['second', 1],
]

/** "in 2 hours" / "5 minutes ago", relative to `now` (injectable so tests do not use the clock). */
export function relativeTime(iso: string, now: number = Date.now()): string {
  const seconds = Math.round((new Date(iso).getTime() - now) / 1000)
  const rtf = new Intl.RelativeTimeFormat(i18n.global.locale.value, { numeric: 'auto' })
  for (const [unit, size] of UNITS) {
    if (Math.abs(seconds) >= size || unit === 'second') {
      return rtf.format(Math.trunc(seconds / size), unit)
    }
  }
  return ''
}

export function absoluteTime(iso: string): string {
  return new Intl.DateTimeFormat(i18n.global.locale.value, {
    dateStyle: 'medium',
    timeStyle: 'medium',
  }).format(new Date(iso))
}
