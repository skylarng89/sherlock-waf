//go:build sherlock_testhooks

package auth

// SetAfterPasswordVerifyHook lets tests in other packages commit a competing
// password change between ChangePassword verifying the current password and
// writing the new one. Compiled only with the sherlock_testhooks tag.
func (s *Service) SetAfterPasswordVerifyHook(fn func()) { s.afterPasswordVerify = fn }
