// Owned by the account page. Add keys here only; never edit locales/index.ts.
export default {
  title: 'Account',
  description: 'Your password and the browser sessions signed in as you.',
  password: {
    heading: 'Change password',
    intro:
      'Changing your password signs out every other browser session. This one stays signed in.',
    current: 'Current password',
    next: 'New password',
    nextHelp: 'At least 12 characters. It must differ from your current password.',
    confirm: 'Confirm new password',
    code: 'Verification code',
    codeHelp:
      'The 6-digit code from your authenticator app. Required because two-step verification is on.',
    codeInvalid: 'Enter the 6-digit code from your authenticator app.',
    tooShort: 'The new password must be at least 12 characters.',
    mismatch: 'The two new passwords do not match.',
    submit: 'Change password',
    saving: 'Changing password',
    done: 'Password changed. Your other sessions have been signed out.',
  },
  sessions: {
    heading: 'Signed-in sessions',
    intro: 'Each browser or device you are signed in on. Sign out any you do not recognise.',
    caption: 'Your signed-in sessions',
    loading: 'Loading sessions',
    loadFailed: 'Your sessions could not be loaded.',
    empty: 'No other sessions.',
    columns: {
      started: 'Started',
      lastActive: 'Last active',
      expires: 'Expires',
      actions: 'Actions',
    },
    current: 'This session',
    revoke: 'Sign out',
    revokeTitle: 'Sign out this session?',
    revokeMessage: 'The browser or device using this session will be signed out immediately.',
    revokeConfirm: 'Sign out session',
    revoked: 'Session signed out.',
  },
}
