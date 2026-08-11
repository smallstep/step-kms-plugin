//go:build !go1.27

package cmd

import (
	"crypto"
	"fmt"
)

func getSignerOptionsDefault(pub crypto.PublicKey) (crypto.SignerOpts, error) {
	return nil, fmt.Errorf("unsupported public key type %T", pub)
}

func verifySignatureDefault(signer crypto.Signer, data, sig []byte, so crypto.SignerOpts) bool {
	return false
}
