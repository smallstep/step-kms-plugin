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
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/smallstep/step-kms-plugin/internal/flagutil"
	"github.com/spf13/cobra"
	"go.step.sm/crypto/kms"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/pemutil"
)

// attestCmd represents the attest command
var attestCmd = &cobra.Command{
	Use:   "attest <uri>",
	Short: "create an attestation certificate",
	Long: `This command, if the KMS supports it, it prints an attestation certificate or an endorsement key.

Currently this command is only supported on YubiKeys.`,
	Example: `  # Get the attestation certificate from a YubiKey:
  step-kms-plugin attest yubikey:slot-id=9c`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return showErrUsage(cmd)
		}

		flags := cmd.Flags()
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

		attester, ok := km.(apiv1.Attester)
		if !ok {
			return fmt.Errorf("%s does not implement Attester", kuri)
		}

		resp, err := attester.CreateAttestation(&apiv1.CreateAttestationRequest{
			Name: args[0],
		})
		if err != nil {
			return fmt.Errorf("failed to attest: %w", err)
		}

		switch {
		case resp.Certificate != nil:
			if err := pem.Encode(os.Stdout, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: resp.Certificate.Raw,
			}); err != nil {
				return fmt.Errorf("failed to encode certificate: %w", err)
			}
			for _, c := range resp.CertificateChain {
				if err := pem.Encode(os.Stdout, &pem.Block{
					Type:  "CERTIFICATE",
					Bytes: c.Raw,
				}); err != nil {
					return fmt.Errorf("failed to encode certificate chain: %w", err)
				}
			}
			return nil
		case resp.PublicKey != nil:
			block, err := pemutil.Serialize(resp.PublicKey)
			if err != nil {
				return err
			}
			return pem.Encode(os.Stdout, block)
		default:
			return errors.New("failed to create attestation: unsupported response")
		}
	},
}

func init() {
	rootCmd.AddCommand(attestCmd)
	attestCmd.SilenceUsage = true
}
