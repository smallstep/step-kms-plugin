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

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt <uri>",
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

		var src, data []byte
		if in != "" {
			if src, err = os.ReadFile(in); err != nil {
				return fmt.Errorf("failed to read file %q: %w", in, err)
			}
		} else {
			if src, err = io.ReadAll(os.Stdin); err != nil {
				return fmt.Errorf("failed to read from STDIN: %w", err)
			}
		}

		switch format {
		case "hex":
			size := hex.DecodedLen(len(src))
			data = make([]byte, size)
			n, err := hex.Decode(data, src)
			if err != nil {
				return fmt.Errorf("failed to decode input: %w", err)
			}
			data = data[:n]
		case "raw":
			data = src
		default:
			size := base64.StdEncoding.DecodedLen(len(src))
			data = make([]byte, size)
			n, err := base64.StdEncoding.Decode(data, src)
			if err != nil {
				return fmt.Errorf("failed to decode input: %w", err)
			}
			data = data[:n]
		}

		km, err := kms.New(context.Background(), apiv1.Options{
			URI: kuri,
		})
		if err != nil {
			return fmt.Errorf("failed to load key manager: %w", err)
		}
		defer km.Close()

		dec, ok := km.(apiv1.Decrypter)
		if !ok {
			return fmt.Errorf("%s does not implement Decrypter", kuri)
		}

		d, err := dec.CreateDecrypter(&apiv1.CreateDecrypterRequest{
			DecryptionKey: kuri,
		})
		if err != nil {
			return err
		}

		var opts crypto.DecrypterOpts
		if oaep {
			opts = &rsa.OAEPOptions{
				Hash:  hash,
				Label: []byte(DefaultOEAPLabel),
			}
		}

		b, err := d.Decrypt(rand.Reader, data, opts)
		if err != nil {
			return fmt.Errorf("error decrypting input: %w", err)
		}
		os.Stdout.Write(b)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(decryptCmd)
	decryptCmd.SilenceUsage = true

	flags := decryptCmd.Flags()
	flags.SortFlags = false

	alg := flagutil.NormalizedValue("alg", []string{"SHA256", "SHA384", "SHA512"}, "SHA256")
	format := flagutil.LowerValue("format", []string{"base64", "hex", "raw"}, "base64")

	flags.Bool("oaep", false, "Use RSA-OAEP instead of RSA PKCS #1 v1.5")
	flags.Var(alg, "alg", "The hashing `algorithm` to use on RSA-OAEP.\nOptions are SHA256, SHA384 or SHA512")
	flags.Var(format, "format", "The `format` to print the signature.\nOptions are base64, hex, or raw")
	flags.String("in", "", "The `file` to decrypt instead of using STDIN.")
}
