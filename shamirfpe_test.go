package shamirfpe_test

import (
	"testing"

	"github.com/hashicorp/vault/shamir"
	"github.com/stretchr/testify/require"
)

// This is just a test unrelated to the library to understand how the vault shamir project works
func Test_SplitCombine(t *testing.T) {
	desiredSecret := []byte("thisisasecretkeythisisasecretkey")
	desiredNumParts := 5
	desiredThreshold := 2
	parts, err := shamir.Split(desiredSecret, desiredNumParts, desiredThreshold)
	require.NoError(t, err)

	// combine first desiredThreshold keys
	combinedSecret, err := shamir.Combine(parts[:desiredThreshold])
	require.NoError(t, err)
	require.Equal(t, desiredSecret, combinedSecret)
}

func Test_NewCipherNoError(t *testing.T) {
	radix := 10   // is this correct for tokenizing digits?
	maxTLen := 32 // max 256 bit tweak
	keyParts := [][]byte{
		[]byte("test me"),
		[]byte("this will"),
		[]byte("fail"),
	}
	tweak := []byte("thisisaknowntweakthisisaknowntwe")
	_, err := NewCipher(radix, maxTLen, keyParts, tweak)
	require.NoError(t, err)
}
