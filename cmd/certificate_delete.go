// Copyright 2022-2026 Smallstep Labs, Inc.
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
	"fmt"

	"github.com/spf13/cobra"

	"go.step.sm/crypto/kms/apiv1"

	"github.com/smallstep/step-kms-plugin/internal/flagutil"
)

var certificateDeleteCmd = &cobra.Command{
	Use:   "delete <uri>",
	Short: "delete a certificate in a KMS",
	Long:  `Deletes a certificate stored in a KMS.`,
	Example: `  # Delete a certificate from a PKCS #11 module:
  step-kms-plugin certificate delete \
  --kms 'pkcs11:module-path=/path/to/libsofthsm2.so;token=softhsm?pin-value=pass' \
  'pkcs11:id=2000;object=my-cert'

  # Delete a certificate from the default TPM KMS:
  step-kms-plugin certificate delete tpmkms:name=my-key

  # Delete an AK certificate from the default TPM KMS:
  step-kms-plugin certificate delete 'tpmkms:name=my-ak;ak=true'`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return showErrUsage(cmd)
		}

		flags := cmd.Flags()

		kuri, name, err := getURIAndNameForFS(flagutil.MustString(flags, "kms"), args[0])
		if err != nil {
			return err
		}

		km, err := openKMS(cmd.Context(), kuri)
		if err != nil {
			return fmt.Errorf("failed to load key manager: %w", err)
		}
		defer km.Close()

		delKMS, ok := km.(interface {
			DeleteCertificate(*apiv1.DeleteCertificateRequest) error
		})
		if !ok {
			return fmt.Errorf("the KMS does not implement the DeleteCertificate method")
		}

		return delKMS.DeleteCertificate(&apiv1.DeleteCertificateRequest{
			Name: name,
		})
	},
}

func init() {
	certificateCmd.AddCommand(certificateDeleteCmd)
	certificateDeleteCmd.SilenceUsage = true
}
