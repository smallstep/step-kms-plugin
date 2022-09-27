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
	"fmt"
	"io/fs"

	"github.com/smallstep/step-kms-plugin/internal/flagutil"
	"github.com/spf13/cobra"
	"go.step.sm/crypto/kms"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/pemutil"
)

// certificateCmd represents the certificate command
var certificateCmd = &cobra.Command{
	Use:   "certificate <uri>",
	Short: "print or import a certificate in a KMS",
	Long:  `This command, if the KMS supports it, it prints or imports a certificate in a KMS.`,
	Example: `  # Import a certificate to a PKCS #11 module:
  step-kms-plugin certificate --import cert.pem \
  --kms 'pkcs11:module-path=/path/to/libsofthsm2.so;token=softhsm?pin-value=pass' \
  'pkcs11:id=2000;object=my-cert'

  # Print a previously store certificate:
  step-kms-plugin certificate \
  --kms 'pkcs11:module-path=/path/to/libsofthsm2.so;token=softhsm?pin-value=pass' \
  'pkcs11:id=2000;object=my-cert'`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return showUsageErr(cmd)
		}

		flags := cmd.Flags()
		certFile := flagutil.MustString(flags, "import")

		kuri := flagutil.MustString(flags, "kms")
		if kuri == "" {
			kuri = args[0]
		}

		// Read a certificate using the CertFS.
		if certFile == "" {
			fsys, err := kms.CertFS(context.TODO(), kuri)
			if err != nil {
				return err
			}

			b, err := fs.ReadFile(fsys, args[0])
			if err != nil {
				return err
			}

			fmt.Print(string(b))
			return nil
		}

		// Import and read certificate using the key manager to avoid opening the kms twice.
		cert, err := pemutil.ReadCertificate(certFile)
		if err != nil {
			return err
		}

		km, err := kms.New(context.Background(), apiv1.Options{
			URI: kuri,
		})
		if err != nil {
			return fmt.Errorf("failed to load key manager: %w", err)
		}
		defer km.Close()

		cm, ok := km.(apiv1.CertificateManager)
		if !ok {
			return fmt.Errorf("%s does not implement a CertificateManager", kuri)
		}
		if err := cm.StoreCertificate(&apiv1.StoreCertificateRequest{
			Name:        args[0],
			Certificate: cert,
		}); err != nil {
			return err
		}
		cert, err = cm.LoadCertificate(&apiv1.LoadCertificateRequest{
			Name: args[0],
		})
		if err != nil {
			return err
		}
		fmt.Print(string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(certificateCmd)
	certificateCmd.SilenceUsage = true

	flags := certificateCmd.Flags()
	flags.SortFlags = false

	flags.String("import", "", "The certificate `file` to import")
}
