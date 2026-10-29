// Owned by the bot-defence UI author (M6-T6). Keys are addressed as bot.<key>.
export default {
  tab: 'Bot defence',
  title: 'Bot defence',
  description:
    'Challenge or block automated clients. A visitor who solves the challenge receives a clearance cookie bound to their network.',
  saved: 'Bot defence saved',
  readOnly: 'You can view this policy but not change it.',
  sections: { general: 'Challenge', rules: 'Rules' },
  enabled: { label: 'Bot defence', switch: 'Challenge suspected bots on this site' },
  challenge: {
    label: 'Challenge type',
    help: 'Proof of work needs no third party. Turnstile and hCaptcha need a provider secret in the server environment.',
    options: { pow: 'Proof of work', turnstile: 'Cloudflare Turnstile', hcaptcha: 'hCaptcha' },
  },
  difficulty: {
    label: 'Difficulty (leading zero hex digits)',
    help: 'Each extra digit makes the browser work about 16 times longer. 4 solves in well under a second.',
  },
  clearanceTtl: {
    label: 'Clearance lifetime',
    help: 'How long a solved challenge stays valid, for example 30m or 12h. From 1m to 7d.',
  },
  siteKey: {
    label: 'Provider site key',
    help: 'The public key of the Turnstile or hCaptcha widget. The secret is never entered here.',
  },
  verifiedBots: {
    label: 'Verified search engine bots',
    help: 'Bots whose user agent and reverse DNS both check out. An unverified claim is treated as any other client.',
    options: { allow: 'Allow', challenge: 'Challenge', block: 'Block' },
  },
  rules: {
    help: 'Rules run in order and the first match decides. Clients with no matching rule are not challenged.',
    empty: 'No rules yet.',
    add: 'Add rule',
    remove: 'Remove rule {n}',
    legend: 'Rule {n}',
    paths: { label: 'Paths', help: 'Comma separated, for example /login, /checkout/*' },
    methods: { label: 'Methods', help: 'Comma separated, for example POST, PUT' },
    countries: {
      label: 'Countries',
      help: 'Two letter codes, comma separated, for example RU, KP',
    },
    reputation: 'Only clients with a bad IP reputation',
    action: {
      label: 'Action',
      options: { challenge: 'Challenge', block: 'Block', allow: 'Allow' },
    },
  },
  stats: {
    title: 'Bot challenges',
    description: 'Challenge outcomes in the last 24 hours.',
    passed: 'Challenges passed',
    failed: 'Challenges failed',
    issued: 'Challenges issued',
    loadError: 'Challenge counts could not be loaded.',
    sampled: 'Counts come from a sample of recent events.',
  },
}
