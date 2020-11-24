package shamirfpe

import (
	"bytes"
	"sync"

	"github.com/capitalone/fpe/ff1"
	"github.com/hashicorp/vault/shamir"
)

// ShamirFpe is the encapsulation type for boostrapping a Cipher
type ShamirFpe struct {
	keyParts [][]byte
	m        sync.Mutex
}

// AddKeyPart adds a key part into the Shamir algorithm
func (sf *ShamirFpe) AddKeyPart(part []byte) {
	sf.m.Lock()
	defer sf.m.Unlock()
	for _, v := range sf.keyParts {
		if bytes.Equal(v, part) {
			return
		}
	}
	sf.keyParts = append(sf.keyParts, part)
}

// NewCipher gives back a new cipher with key from shamir alg
func (sf *ShamirFpe) NewCipher(radix int, maxTLen int, tweak []byte) (ff1.Cipher, error) {
	key, err := shamir.Combine(sf.keyParts)
	if err != nil {
		return ff1.Cipher{}, err
	}
	return ff1.NewCipher(radix, maxTLen, key, tweak)
}
