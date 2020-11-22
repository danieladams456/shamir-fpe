package shamirfpe

import (
	"testing"
)

func Test_NewCipher(t *testing.T) {
	radix := 10   // is this correct for tokenizing digits?
	maxTLen := 32 // max 256 bit tweak
	tweak := []byte("thisisaknowntweakthisisaknowntwe")
	NewCipher(radix, maxTLen, tweak)
}
