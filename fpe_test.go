package shamirfpe

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_NewCipherNoError(t *testing.T) {
	radix := 10   // is this correct for tokenizing digits?
	maxTLen := 32 // max 256 bit tweak
	tweak := []byte("thisisaknowntweakthisisaknowntwe")
	_, err := NewCipher(radix, maxTLen, tweak)
	require.NoError(t, err)
}
