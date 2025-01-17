package crypto

import "crypto/ed25519"

type PrivateKey struct {
	key ed25519.PrivateKey
}
