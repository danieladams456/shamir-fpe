package shamirfpe_test

import (
	"testing"

	"github.com/danieladams456/shamirfpe"
	"github.com/hashicorp/vault/shamir"
	"github.com/stretchr/testify/require"
)

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

func Test_PrecomputedKeys(t *testing.T) {
	part1 := []byte{214, 7, 14, 198, 56, 250, 191, 191, 4, 102, 186, 207, 227, 182, 113, 237, 55, 228, 214, 4, 113, 158, 60, 199, 236, 58, 240, 108, 109, 75, 192, 146, 222}
	part2 := []byte{11, 214, 8, 222, 12, 161, 81, 161, 166, 87, 134, 115, 153, 59, 196, 97, 3, 31, 238, 116, 183, 209, 120, 188, 54, 250, 47, 250, 104, 170, 107, 254, 20}
	maxTLen := 32 // max 256 bit tweak
	sf := shamirfpe.ShamirFpe{}
	sf.AddKeyPart(part1)
	sf.AddKeyPart(part2)

	testCases := []struct {
		radix      int
		tweak      string
		plaintext  string
		ciphertext string
	}{
		{
			radix:      36,
			tweak:      "test_tweak",
			plaintext:  "plaintext12345",
			ciphertext: "bab75y05yinscu",
		},
	}

	for _, test := range testCases {
		c, err := sf.NewCipher(test.radix, maxTLen, []byte(test.tweak))

		ciphertext, err := c.Encrypt(test.plaintext)
		require.NoError(t, err)
		require.Equal(t, ciphertext, test.ciphertext)

		plaintext, err := c.Decrypt(ciphertext)
		require.NoError(t, err)
		require.Equal(t, plaintext, test.plaintext)
	}
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
