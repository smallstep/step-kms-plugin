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
	"fmt"
	"io/fs"

	"github.com/smallstep/step-kms-plugin/internal/flagutil"
	"github.com/spf13/cobra"
	"go.step.sm/crypto/kms"
)

// keyCmd represents the key command
var keyCmd = &cobra.Command{
	Use:   "key <uri>",
	Short: "print the public key in a kms",
	Long:  `Prints a public key stored in a KMS.`,
	Example: `  # Get the public key defining the kms uri and key together:
  step-kms-plugin key \
  "pkcs11:module-path=/path/to/libsofthsm2.so;token=softhsm;id=1000?pin-value=pass"

  # Get the public key using a PKCS #11 id:
  step-kms-plugin key \
  --kms "pkcs11:module-path=/path/to/libsofthsm2.so;token=softhsm?pin-value=pass" \
  "pkcs11:id=1000"

  # Get the public key using the PKCS #11 label:
  step-kms-plugin key \
  --kms "pkcs11:module-path=/path/to/libsofthsm2.so;token=softhsm?pin-source=/var/run/pass.txt" \
  "pkcs11:object=my-key"

  # Get the public key from Google's Cloud KMS:
  step-kms-plugin key --kms cloudkms: \
  projects/my-project/locations/us-west1/keyRings/my-keyring/cryptoKeys/my-rsa-key/cryptoKeyVersions/1

  # Get the public key from Azure's Key Vault:
  step-kms-plugin key 'azurekms:vault=my-key-vault;name=my-key'

  # Get the public key key from AWS KMS.
  step-kms-plugin key 'awskms:key-id=acbebc8f-822d-4c1c-b5d1-eb3a8fcaced7;region=us-west-1'

  # Get key from a YubiKey:
  step-kms-plugin key yubikey:slot-id=82

  # Get a key from the ssh-agent
  step-kms-plugin key sshagentkms:user@localhost`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return showUsageErr(cmd)
		}

		flags := cmd.Flags()
		kuri := flagutil.MustString(flags, "kms")
		if kuri == "" {
			kuri = args[0]
		}

		fsys, err := kms.KeyFS(context.TODO(), kuri)
		if err != nil {
			return err
		}

		b, err := fs.ReadFile(fsys, args[0])
		if err != nil {
			return err
		}

		fmt.Print(string(b))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(keyCmd)
	keyCmd.SilenceUsage = true
}
