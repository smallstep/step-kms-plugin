// Copyright 2022 Smallstep Labs, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package cmd

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/smallstep/step-kms-plugin/internal/flagutil"
	"github.com/spf13/cobra"
	"go.step.sm/crypto/kms"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/sshutil"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// signCmd represents the sign command
var signCmd = &cobra.Command{
	Use:   "sign <uri> [<digest>]",
	Short: "sign the given digest using the kms",
	Long: `Signs a digest or a file using a key in the KMS.

When a digest is passed this must be using hexadecimal encoding, but when this
command is used as a plugin by step, or when the digest or the message to sign
is passed as plain bytes on stdin without any special encoding.`,
	Example: `  # Signs the given file using a key in the PKCS #11 module.
  step-kms-plugin --in data.bin \
  --kms 'pkcs11:module-path=/path/to/libsofthsm2.so;token=softhsm?pin-value=pass' \
  'pkcs11:id=1000'

  # Signs a digest using a key in Google's Cloud KMS.
  step-kms-plugin 1b8de4254213f8c3f784b3da4611eaeec1e720e74b4357029f8271b4ef9e1c2c \
  --kms cloudkms: \
  projects/my-project/locations/us-west1/keyRings/my-keyring/cryptoKeys/my-rsa-key/cryptoKeyVersions/1

  # Signs and verify using RSA PKCS #1 with SHA512:
  step-kms-plugin --in data.bin --verify --alg SHA512 \
  --kms 'pkcs11:module-path=/path/to/libsofthsm2.so;token=softhsm?pin-value=pass' \
  'pkcs11:object=my-rsa-key'

  # Sign a file using an Ed25519 key in the ssh-agent :
  step-kms-plugin sign --in data.bin sshagentkms:user@localhost`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if l := len(args); l != 1 && l != 2 {
			return showUsageErr(cmd)
		}

		flags := cmd.Flags()
		alg := flagutil.MustString(flags, "alg")
		pss := flagutil.MustBool(flags, "pss")
		format := flagutil.MustString(flags, "format")
		in := flagutil.MustString(flags, "in")
		verify := flagutil.MustBool(flags, "verify")

		kuri := flagutil.MustString(flags, "kms")
		if kuri == "" {
			kuri = args[0]
		}

		km, err := kms.New(context.Background(), apiv1.Options{
			URI: kuri,
		})
		if err != nil {
			return fmt.Errorf("failed to load key manager: %w", err)
		}
		defer km.Close()

		signer, err := km.CreateSigner(&apiv1.CreateSignerRequest{
			SigningKey: args[0],
		})
		if err != nil {
			return fmt.Errorf("failed to create signer: %w", err)
		}

		pub := signer.Public()
		so, err := getSignerOptions(pub, alg, pss)
		if err != nil {
			return err
		}

		var digest []byte
		switch {
		case in != "":
			data, err := os.ReadFile(in)
			if err != nil {
				return fmt.Errorf("failed to read file %q: %w", in, err)
			}
			if signsRawInput(pub) {
				digest = data
			} else if hashFunc := so.HashFunc(); hashFunc != 0 {
				h := hashFunc.New()
				h.Write(data)
				digest = h.Sum(nil)
			} else {
				digest = data
			}
		case len(args) == 2:
			if signsRawInput(pub) {
				return fmt.Errorf("flag --in is required for type %T", pub)
			}
			digest, err = hex.DecodeString(args[1])
			if err != nil {
				return fmt.Errorf("failed to decode digest: %w", err)
			}
		default:
			// Data passed by stdin is in binary form.
			digest, err = ioutil.ReadAll(os.Stdin)
			if err != nil {
				return err
			}
		}

		sig, err := signer.Sign(rand.Reader, digest, so)
		if err != nil {
			return err
		}

		if verify {
			if !verifySignature(signer, digest, sig, so) {
				return fmt.Errorf("failed to verify the signature")
			}
		}

		switch format {
		case "hex":
			fmt.Println(hex.EncodeToString(sig))
		case "raw":
			os.Stdout.Write(sig)
		default:
			fmt.Println(base64.StdEncoding.EncodeToString(sig))
		}

		return nil
	},
}

func signsRawInput(pub crypto.PublicKey) bool {
	switch pub.(type) {
	case ed25519.PublicKey:
		return true
	case ssh.PublicKey:
		return true
	default:
		return false
	}
}

func getSignerOptions(pub crypto.PublicKey, alg string, pss bool) (crypto.SignerOpts, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return crypto.SHA256, nil
		case elliptic.P384():
			return crypto.SHA384, nil
		case elliptic.P521():
			return crypto.SHA512, nil
		default:
			return nil, fmt.Errorf("unsupported elliptic curve %q", k.Curve.Params().Name)
		}
	case *rsa.PublicKey:
		var h crypto.Hash
		switch alg {
		case "", "SHA256":
			h = crypto.SHA256
		case "SHA384":
			h = crypto.SHA384
		case "SHA512":
			h = crypto.SHA512
		default:
			return nil, fmt.Errorf("unsupported hashing algorithm %q", alg)
		}
		if pss {
			return &rsa.PSSOptions{
				Hash:       h,
				SaltLength: rsa.PSSSaltLengthAuto,
			}, nil
		}
		return h, nil
	case ed25519.PublicKey:
		return crypto.Hash(0), nil
	case ssh.PublicKey, *agent.Key:
		pk, err := sshutil.CryptoPublicKey(pub)
		if err != nil {
			return nil, err
		}
		return getSignerOptions(pk, alg, pss)
	default:
		return nil, fmt.Errorf("unsupported public key type %T", pub)
	}
}

func verifySignature(signer crypto.Signer, data, sig []byte, so crypto.SignerOpts) bool {
	switch pub := signer.Public().(type) {
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(pub, data, sig)
	case *rsa.PublicKey:
		if pss, ok := so.(*rsa.PSSOptions); ok {
			return rsa.VerifyPSS(pub, so.HashFunc(), data, sig, pss) == nil
		} else {
			return rsa.VerifyPKCS1v15(pub, so.HashFunc(), data, sig) == nil
		}
	case ed25519.PublicKey:
		return ed25519.Verify(pub, data, sig)
	case ssh.PublicKey:
		// Attempt to use the last signature if available.
		if s, ok := signer.(interface{ LastSignature() *ssh.Signature }); ok {
			if sshSig := s.LastSignature(); sshSig != nil {
				return pub.Verify(data, s.LastSignature()) == nil
			}
		}
		// Verify using the resulting signature.
		// It won't work with sk keys.
		return pub.Verify(data, &ssh.Signature{
			Format: sshFormat(pub, so),
			Blob:   sig,
		}) == nil
	default:
		return false
	}
}

func sshFormat(pub ssh.PublicKey, so crypto.SignerOpts) string {
	if pub.Type() == ssh.KeyAlgoRSA {
		switch so.HashFunc() {
		case crypto.SHA256:
			return ssh.SigAlgoRSASHA2256
		case crypto.SHA512:
			return ssh.SigAlgoRSASHA2512
		case crypto.SHA1:
			return ssh.SigAlgoRSA
		}
	}
	return pub.Type()

}

func init() {
	rootCmd.AddCommand(signCmd)
	signCmd.SilenceUsage = true

	flags := signCmd.Flags()
	flags.SortFlags = false

	alg := flagutil.NormalizedValue("alg", []string{"SHA256", "SHA384", "SHA512"}, "SHA256")
	format := flagutil.LowerValue("format", []string{"base64", "hex", "raw"}, "base64")

	flags.Var(alg, "alg", "The hashing `algorithm` to use on RSA PKCS #1 and RSA-PSS signatures.\nOptions are SHA256, SHA384 or SHA512")
	flags.Bool("pss", false, "Use RSA-PSS signature scheme instead of RSA PKCS #1")
	flags.Var(format, "format", "The `format` to print the signature.\nOptions are base64, hex, or raw")
	flags.String("in", "", "The `file` to sign. Required for Ed25519 keys.")
	flags.Bool("verify", false, "Verify the signature with the public key")
}
