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
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/smallstep/step-kms-plugin/internal/flagutil"
	"github.com/spf13/cobra"
	"go.step.sm/crypto/kms"
	"go.step.sm/crypto/kms/apiv1"
)

// DefaultOEAPLabel is the label used when OAEP is used.
const DefaultOEAPLabel = "step-kms-plugin/v1/oaep"

// encryptCmd represents the encrypt command
var encryptCmd = &cobra.Command{
	Use:   "encrypt <uri>",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if l := len(args); l != 1 {
			return showErrUsage(cmd)
		}

		flags := cmd.Flags()
		kuri := flagutil.MustString(flags, "kms")
		if kuri == "" {
			kuri = args[0]
		}

		oaep := flagutil.MustBool(flags, "oaep")
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

		km, err := kms.New(context.Background(), apiv1.Options{
			URI: kuri,
		})
		if err != nil {
			return fmt.Errorf("failed to load key manager: %w", err)
		}
		defer km.Close()

		key, err := km.GetPublicKey(&apiv1.GetPublicKeyRequest{
			Name: kuri,
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
			if b, err = rsa.EncryptOAEP(hash.New(), rand.Reader, pub, data, []byte(DefaultOEAPLabel)); err != nil {
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
	flags.Var(alg, "alg", "The hashing `algorithm` to use on RSA-OAEP.\nOptions are SHA256, SHA384 or SHA512")
	flags.Var(format, "format", "The `format` used in the input.\nOptions are base64, hex, or raw")
	flags.String("in", "", "The `file` to encrypt instead of using STDIN.")
}
