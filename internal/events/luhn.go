package events

// Luhn reports whether the digit string passes the Luhn checksum. Non-digit
// bytes make it false.
func Luhn(digits string) bool {
	if len(digits) == 0 {
		return false
	}
	sum, double := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		c := digits[i]
		if c < '0' || c > '9' {
			return false
		}
		d := int(c - '0')
		if double {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}
