// Fintech baseline preset (M11-T3). Keys are addressed as fintech.<key>.
export default {
  title: 'Fintech baseline',
  intro:
    'Applies the recommended finance settings to this site: login protection, data protection and the bot challenge it relies on. You review every change before it is applied.',
  review: 'Review baseline',
  hide: 'Hide baseline',
  apply: 'Apply baseline',
  applying: 'Applying baseline',
  applied: 'Fintech baseline applied',
  nothing: 'This site already matches the baseline.',
  modeHint:
    'This site is in {mode} mode. The baseline does not change the mode, so these protections only record findings until you switch the site to block.',
  endpointsPrompt:
    'The baseline cannot know your login paths. Login protection stays inactive until you declare them on the Login protection tab.',
  table: {
    caption: 'Changes the baseline would make',
    setting: 'Setting',
    current: 'Now',
    baseline: 'Baseline',
    result: 'Result',
  },
  status: {
    set: 'Will be set',
    unchanged: 'Already set',
    kept: 'Kept (yours differs)',
    overwrite: 'Will be replaced',
  },
  replace: 'Replace my value for {setting}',
  unset: 'not set',
  fields: {
    login_protection_enabled: 'Login protection enabled',
    login_protection_thresholds_per_ip: 'Login failures per client address',
    login_protection_thresholds_per_username: 'Login failures per username',
    login_protection_thresholds_per_device: 'Login failures per device',
    login_protection_thresholds_window: 'Login failure window',
    login_protection_action: 'Login action over a threshold',
    dlp_enabled: 'Data protection enabled',
    dlp_detect: 'Data protection detectors',
    dlp_action: 'Data protection action',
    bot_enabled: 'Bot challenge enabled',
    bot_challenge: 'Bot challenge type',
  },
  noWrite: 'You can review the baseline but not apply it.',
}
