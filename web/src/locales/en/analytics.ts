// Owned by the analytics author (M7-T3). Keys are addressed as analytics.<key>.
export default {
  title: 'Analytics',
  description: 'Traffic and attack trends. Every chart has a table with the same numbers.',
  range: 'Time range',
  site: 'Site',
  allSites: 'All sites',
  ranges: { '1h': 'Last hour', '6h': 'Last 6 hours', '24h': 'Last 24 hours', '7d': 'Last 7 days' },
  loading: 'Loading analytics',
  loadError: 'This panel could not be loaded.',
  empty: 'No data in this period.',
  viewChart: 'View as chart',
  viewTable: 'View as table',
  sampled: 'Computed from a capped sample of events, so counts are approximate.',
  series: {
    title: 'Requests, blocks and challenges over time',
    ariaLabel:
      'Line chart of requests by action over time. A table with the same numbers is available.',
    tableCaption: 'Requests by action and time bucket',
    time: 'Time',
    total: 'Total',
  },
  top: {
    count: 'Events',
    rank: 'Rank',
    chartLabel:
      'Bar chart of the {n} most frequent values. A table with the same numbers is available.',
    tableCaption: 'Most frequent values',
    site: { title: 'Top sites', value: 'Site' },
    rule: { title: 'Top rules', value: 'Rule' },
    ip: { title: 'Top client IPs', value: 'IP address' },
    path: { title: 'Top paths', value: 'Path' },
    country: { title: 'Top countries', value: 'Country' },
  },
}
