package shamirfpe_test

import (
	"testing"

	"github.com/danieladams456/shamirfpe"
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

func Test_NewCipherErrorsNonEqualLength(t *testing.T) {
	radix := 10   // for tokenizing digits
	maxTLen := 32 // max 256 bit tweak
	tweak := []byte("test_tweak")

	sf := shamirfpe.ShamirFpe{}
	sf.AddKeyPart([]byte("test me"))
	sf.AddKeyPart([]byte("this will"))
	sf.AddKeyPart([]byte("fail"))
	_, err := sf.NewCipher(radix, maxTLen, tweak)
	require.EqualError(t, err, "all parts must be the same length")
}
