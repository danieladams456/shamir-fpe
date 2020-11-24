package shamirfpe_test

import (
	"testing"

	"github.com/danieladams456/shamirfpe"
	"github.com/hashicorp/vault/shamir"
	"github.com/stretchr/testify/require"
)

// This is just a test unrelated to the library to understand how the vault shamir project works
func Test_EndToEnd(t *testing.T) {
	desiredSecret := []byte("thisisasecretkeythisisasecretkey")
	desiredNumParts := 5
	desiredThreshold := 2
	parts, err := shamir.Split(desiredSecret, desiredNumParts, desiredThreshold)
	require.NoError(t, err)

	sf := shamirfpe.ShamirFpe{}
	// combine first desiredThreshold keys
	for _, v := range parts[:desiredThreshold] {
		sf.AddKeyPart(v)
	}

	// construct shamirfpe
	radix := 36   // for tokenizing digits + letters (case insensitive)
	maxTLen := 32 // max 256 bit tweak
	tweak := []byte("test_tweak")
	c, err := sf.NewCipher(radix, maxTLen, tweak)
	require.NoError(t, err)

	plaintext := "testplaintext"
	ciphertext, err := c.Encrypt(plaintext)
	require.NoError(t, err)
	decrypted, err := c.Decrypt(ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
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
