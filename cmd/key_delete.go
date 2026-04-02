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

var keyDeleteCmd = &cobra.Command{
	Use:   "delete <uri>",
	Short: "delete a key in a KMS",
	Long:  `Deletes a key stored in a KMS.`,
	Example: `  # Delete a key from a PKCS #11 module:
  step-kms-plugin key delete \
  --kms 'pkcs11:module-path=/path/to/libsofthsm2.so;token=softhsm?pin-value=pass' \
  'pkcs11:id=1000;object=my-key'

  # Delete a key from Google's Cloud KMS:
  step-kms-plugin key delete \
  cloudkms:projects/my-project/locations/us-west1/keyRings/my-keyring/cryptoKeys/my-rsa-key/cryptoKeyVersions/1

  # Delete a key from Azure's Key Vault:
  step-kms-plugin key delete 'azurekms:vault=my-key-vault;name=my-key'

  # Delete a key from the default TPM KMS:
  step-kms-plugin key delete tpmkms:name=my-key`,
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
			DeleteKey(*apiv1.DeleteKeyRequest) error
		})
		if !ok {
			return fmt.Errorf("the KMS does not implement the DeleteKey method")
		}

		return delKMS.DeleteKey(&apiv1.DeleteKeyRequest{
			Name: name,
		})
	},
}

func init() {
	keyCmd.AddCommand(keyDeleteCmd)
	keyDeleteCmd.SilenceUsage = true
}
