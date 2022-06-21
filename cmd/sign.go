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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"go.step.sm/crypto/kms"
	"go.step.sm/crypto/kms/apiv1"
)

// signCmd represents the sign command
var signCmd = &cobra.Command{
	Use:   "sign <uri> <digest>",
	Short: "sign the given digest using the kms",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 2 {
			cmd.SilenceErrors = true
			return errors.New("usage")
		}

		kuri, _ := cmd.Flags().GetString("kms")
		if kuri == "" {
			kuri = args[0]
		}

		cmd.SilenceUsage = true
		km, err := kms.New(context.Background(), apiv1.Options{
			URI: kuri,
		})
		if err != nil {
			return fmt.Errorf("failed to load key manager: %w", err)
		}
		defer km.Close()

		digest, err := hex.DecodeString(args[1])
		if err != nil {
			return err
		}

		signer, err := km.CreateSigner(&apiv1.CreateSignerRequest{
			SigningKey: args[0],
		})
		if err != nil {
			return fmt.Errorf("failed to create signer: %w", err)
		}

		sig, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
		if err != nil {
			return err
		}

		fmt.Println(hex.EncodeToString(sig))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(signCmd)
	signCmd.Flags().String("kms", "", "Uri with the kms configuration to use")
}
