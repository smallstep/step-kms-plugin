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
)

// signCmd represents the sign command
var signCmd = &cobra.Command{
	Use:   "sign <uri> [<digest>]",
	Short: "sign the given digest using the kms",
	RunE: func(cmd *cobra.Command, args []string) error {
		if l := len(args); l != 1 && l != 2 {
			return showUsageErr(cmd)
		}

		flags := cmd.Flags()
		alg := flagutil.MustString(flags, "alg")
		pss := flagutil.MustBool(flags, "pss")
		format := flagutil.MustString(flags, "format")

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

		var digest []byte
		if len(args) == 2 {
			digest, err = hex.DecodeString(args[1])
			if err != nil {
				return err
			}
		} else {
			digest, err = ioutil.ReadAll(os.Stdin)
			if err != nil {
				return err
			}
		}

		signer, err := km.CreateSigner(&apiv1.CreateSignerRequest{
			SigningKey: args[0],
		})
		if err != nil {
			return fmt.Errorf("failed to create signer: %w", err)
		}

		so, err := getSignerOptions(signer.Public(), alg, pss)
		if err != nil {
			return err
		}

		sig, err := signer.Sign(rand.Reader, digest, so)
		if err != nil {
			return err
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
	default:
		return nil, fmt.Errorf("unsupported public key type %T", pub)
	}
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
}
