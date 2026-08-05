//go:build go1.27

package cmd

import (
	"crypto"
	"crypto/mldsa"
	"fmt"
)

func getSignerOptionsDefault(pub crypto.PublicKey) (crypto.SignerOpts, error) {
	switch pub.(type) {
	case *mldsa.PublicKey:
		return crypto.Hash(0), nil
	default:
		return nil, fmt.Errorf("unsupported public key type %T", pub)
	}
}

func verifySignatureDefault(signer crypto.Signer, data, sig []byte, so crypto.SignerOpts) bool {
	opts, _ := so.(*mldsa.Options)
	switch pub := signer.Public().(type) {
	case *mldsa.PublicKey:
		return mldsa.Verify(pub, data, sig, opts) == nil
	default:
		return false
	}
}
