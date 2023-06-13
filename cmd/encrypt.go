// Copyright 2022 Smallstep Labs, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package cmd

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"go.step.sm/crypto/kms"
	"go.step.sm/crypto/kms/apiv1"

	"github.com/smallstep/step-kms-plugin/internal/flagutil"
)

// DefaultOEAPLabel is the label used when OAEP is used.
const DefaultOEAPLabel = "step-kms-plugin/v1/oaep"

// encryptCmd represents the encrypt command
var encryptCmd = &cobra.Command{
	Use:   "encrypt <uri>",
	Short: "encrypt a given input with an RSA public key",
	Long: `Encrypts a given input with an RSA public key. 

This command supports encrypting a short message (eg. a password) with RSA and
the padding scheme from PKCS #1 v1.5 or using RSA-OAEP. The messages must not be
longer than the size of the key minus a number of bytes that depend on the
scheme used.

All KMSs support encryption, because only the public key is used. Support for
decryption is currently limited to YubiKey, Google Cloud KMS and some PKCS #11 KMSs. 
Not all devices support both schemes. YubiKeys do: they support PKCS #1 v1.5 via the PIV
application, and they support RSA-OAEP via the YubiKey PKCS #11 library, YKCS11.
Other PKCS #11 devices (including YubiHSM2) will generally support both
PKCS #1 v.1.5 and RSA-OAEP. Google Cloud KMS only supports RSA-OAEP and doesn't 
support labels, so you should use "--no-label" when encrypting to a key in Google
Cloud KMS.`,
	Example: `  # Encrypt a password given by stdin using RSA PKCS#1 v1.5:
  echo password | step-kms-plugin encrypt yubikey:slot-id=82

  # Encrypt a given file using RSA-OAEP:
  step-kms-plugin encrypt --oaep --in message.txt \
    --kms 'pkcs11:module-path=/usr/local/lib/pkcs11/yubihsm_pkcs11.dylib;token=YubiHSM?pin-value=0001password' \
	'pkcs11:object=my-rsa-key'

  # Encrypt a given file using RSA-OAEP without an OAEP label:
  step-kms-plugin encrypt --oaep --in message.txt --no-label \
  --kms 'cloudkms:' \
  'projects/my-project-id/locations/global/keyRings/my-decrypter-ring/cryptoKeys/my-decrypter/cryptoKeyVersions/1'

  # Encrypt a given file using RSA-OAEP and a custom label:
  step-kms-plugin encrypt --oaep --in message.txt --label my-custom-label \
    --kms 'pkcs11:module-path=/usr/local/lib/pkcs11/yubihsm_pkcs11.dylib;token=YubiHSM?pin-value=0001password' \
	'pkcs11:object=my-rsa-key'

  # Encrypt a given file using a key in disk using the hexadecimal format:
  step-kms-plugin encrypt --format hex --in message.txt --kms softkms: rsa.pub
  
  # Encrypt a given file using an Attestation Key in the default TPM KMS:
  step kms encrypt --in message.txt 'tpmkms:my-ak;ak=true'

  # Encrypt a given file using a key in the default TPM KMS:
  step kms encrypt --in message.txt tpmkms:my-key`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if l := len(args); l != 1 {
			return showErrUsage(cmd)
		}

		name := args[0]
		flags := cmd.Flags()
		kuri := ensureSchemePrefix(flagutil.MustString(flags, "kms"))
		if kuri == "" {
			kuri = name
		}

		oaep := flagutil.MustBool(flags, "oaep")
		label := flagutil.MustString(flags, "label")
		noLabel := flagutil.MustBool(flags, "no-label")
		format := flagutil.MustString(flags, "format")
		in := flagutil.MustString(flags, "in")

		// OAEP requires a hash algorithm.
		// It uses SHA256 by default.
		var hash crypto.Hash
		var err error
		if oaep {
			alg := flagutil.MustString(flags, "alg")
			if hash, err = getHashAlgorithm(alg); err != nil {
				return err
			}
		}

		// Read input
		var data []byte
		if in != "" {
			if data, err = os.ReadFile(in); err != nil {
				return fmt.Errorf("failed to read file %q: %w", in, err)
			}
		} else {
			if data, err = io.ReadAll(os.Stdin); err != nil {
				return fmt.Errorf("failed to read from STDIN: %w", err)
			}
		}

		km, err := kms.New(cmd.Context(), apiv1.Options{
			URI: kuri,
		})
		if err != nil {
			return fmt.Errorf("failed to load key manager: %w", err)
		}
		defer km.Close()

		key, err := km.GetPublicKey(&apiv1.GetPublicKeyRequest{
			Name: name,
		})
		if err != nil {
			return fmt.Errorf("failed to get the public key: %w", err)
		}

		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%s is not an RSA key", kuri)
		}

		var b []byte
		if oaep {
			var oaepLabel []byte
			switch {
			case noLabel:
				break // nothing to do
			default:
				oaepLabel = []byte(label)
			}
			if b, err = rsa.EncryptOAEP(hash.New(), rand.Reader, pub, data, oaepLabel); err != nil {
				return err
			}
		} else {
			if b, err = rsa.EncryptPKCS1v15(rand.Reader, pub, data); err != nil {
				return err
			}
		}

		switch format {
		case "hex":
			fmt.Println(hex.EncodeToString(b))
		case "raw":
			os.Stdout.Write(b)
		default:
			fmt.Println(base64.StdEncoding.EncodeToString(b))
		}

		return nil
	},
}

func getHashAlgorithm(alg string) (crypto.Hash, error) {
	switch alg {
	case "", "SHA256":
		return crypto.SHA256, nil
	case "SHA384":
		return crypto.SHA384, nil
	case "SHA512":
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported hashing algorithm %q", alg)
	}
}

func init() {
	rootCmd.AddCommand(encryptCmd)
	encryptCmd.SilenceUsage = true

	flags := encryptCmd.Flags()
	flags.SortFlags = false

	alg := flagutil.NormalizedValue("alg", []string{"SHA256", "SHA384", "SHA512"}, "SHA256")
	format := flagutil.LowerValue("format", []string{"base64", "hex", "raw"}, "base64")

	flags.Bool("oaep", false, "Use RSA-OAEP instead of RSA PKCS #1 v1.5")
	flags.Bool("no-label", false, "Omit setting the label when RSA-OAEP is used")
	flags.String("label", DefaultOEAPLabel, "Set a label when using RSA-OAEP")
	flags.Var(alg, "alg", "The hashing `algorithm` to use on RSA-OAEP.\nOptions are SHA256, SHA384 or SHA512")
	flags.Var(format, "format", "The `format` used in the input.\nOptions are base64, hex, or raw")
	flags.String("in", "", "The `file` to encrypt instead of using STDIN.")
}
