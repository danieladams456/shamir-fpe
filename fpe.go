package shamirfpe

import (
	"github.com/capitalone/fpe/ff1"
)

// NewCipher gives back a new cipher with key from shamir alg
func NewCipher(radix int, maxTLen int, tweak []byte) (ff1.Cipher, error) {
	key := getKey()
	return ff1.NewCipher(radix, maxTLen, key, tweak)
}
