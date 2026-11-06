// Data protection tab (M11-T3). Keys are addressed as dlp.<key>.
export default {
  tab: 'Data protection',
  title: 'Data protection',
  description:
    'Find card numbers, IBANs and custom patterns in responses and mask or block them before they leave.',
  saved: 'Data protection saved',
  readOnly: 'You can view this policy but not change it.',
  sections: {
    general: 'Data protection',
    detect: 'What to look for',
    patterns: 'Custom patterns',
    scope: 'Which responses are scanned',
  },
  enabled: { label: 'Data protection', switch: 'Scan responses from this site' },
  mode: {
    detect:
      'This site is in detect mode. Matches are recorded but responses are never changed: nothing is masked or blocked.',
    off: 'This site is in off mode. Data protection does nothing until the site is switched to detect or block.',
  },
  privacy:
    'Matched values are never stored. Events, logs and exports record only the detector and a count, never the value that matched.',
  inherited: 'Inherited: {value}',
  builtin: 'Default: {value}',
  detect: {
    help: 'Switch on the detectors to run. Leave all unset to inherit.',
    pan: 'Payment card numbers (checked with the Luhn algorithm)',
    iban: 'IBANs (checked with mod-97)',
    custom: 'Custom: {name}',
    none: 'No detector is selected, so nothing is scanned.',
  },
  patterns: {
    help: 'Go (RE2) regular expressions. They cannot cause catastrophic backtracking, and must not match the empty string. Look-ahead, look-behind and back-references are not supported.',
    empty: 'No custom patterns at this level.',
    legend: 'Pattern {n}',
    add: 'Add pattern',
    remove: 'Remove pattern {n}',
    name: {
      label: 'Name',
      help: 'Lower-case letters, digits and underscores, starting with a letter.',
    },
    pattern: { label: 'Regular expression', help: 'At most 512 characters.' },
  },
  action: {
    label: 'Action on a match',
    help: 'Mask replaces all but the last four characters. Block replaces the whole response with the block page.',
    mask: 'Mask',
    block: 'Block',
    log: 'Log only',
  },
  contentTypes: {
    label: 'Scanned content types',
    help: 'One media type or prefix per line, such as application/json or text/. Other responses are passed through.',
  },
  maxBody: {
    label: 'Largest response scanned (bytes)',
    help: 'Larger responses pass through unscanned and are counted. 1024 to 16777216.',
  },
  errors: {
    action: 'Choose mask, block or log.',
    bodySize: 'Enter a whole number from 1024 to 16777216.',
    contentType: 'Use a media type or prefix such as text/ or application/json.',
    tooManyPatterns: 'At most 20 patterns.',
    name: 'Use lower-case letters, digits and underscores, starting with a letter (at most 32).',
    duplicateName: 'Another pattern already has this name.',
    patternRequired: 'Enter a regular expression.',
    patternLong: 'At most 512 characters.',
    notRe2: 'Look-ahead, look-behind and back-references are not supported.',
  },
}
