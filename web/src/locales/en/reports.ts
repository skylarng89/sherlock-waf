// Owned by the reports author (M7-T4). Keys are addressed as reports.<key>.
export default {
  title: 'Would-block report',
  description:
    'Requests a detect-mode site would have blocked, to review before you switch it to block mode.',
  site: 'Site',
  range: 'Time range',
  ranges: { '24h': 'Last 24 hours', '7d': 'Last 7 days', '30d': 'Last 30 days' },
  noSites: 'No sites configured',
  noSitesDescription: 'Add a site first, then come back to see what block mode would do.',
  loading: 'Loading report',
  loadError: 'The report could not be loaded.',
  mode: 'Current mode',
  notDetect:
    'This site is not in detect mode. The report only lists requests that were let through while the site was observing.',
  total: 'Requests that would have been blocked',
  truncated: 'More matching requests exist than were analysed, so the counts are a lower bound.',
  clean: {
    title: 'Nothing would have been blocked',
    description: 'No request reached the blocking threshold in this period.',
  },
  byRule: {
    title: 'By rule',
    caption: 'Would-block requests grouped by rule',
    rule: 'Rule',
    count: 'Requests',
  },
  byPath: {
    title: 'By path',
    caption: 'Would-block requests grouped by path',
    path: 'Path',
    count: 'Requests',
  },
  requests: {
    title: 'Most recent requests',
    caption: 'The most recent would-block requests',
    time: 'Time',
    client: 'Client',
    request: 'Request',
    rules: 'Rules',
    open: 'Open event {id}',
  },
  export: { label: 'Export CSV', done: 'CSV exported', failed: 'The CSV could not be exported.' },
  switch: {
    label: 'Switch to block mode',
    title: 'Review before switching',
    hint: 'Look through the rules and paths above. Legitimate traffic in this list means a false positive: tune the rule first.',
    done: '{site} is now in block mode',
  },
}
