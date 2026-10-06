package pcv3

import "math/bits"

func checkedAdd64(left, right uint64) (uint64, bool) {
	sum, carry := bits.Add64(left, right, 0)
	return sum, carry == 0
}

func checkedMul64(left, right uint64) (uint64, bool) {
	high, low := bits.Mul64(left, right)
	return low, high == 0
}

func checkedCeilDiv64(value, divisor uint64) (uint64, bool) {
	quotient := value / divisor
	if value%divisor == 0 {
		return quotient, true
	}
	return checkedAdd64(quotient, 1)
}
