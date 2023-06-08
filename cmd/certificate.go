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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"

	"github.com/spf13/cobra"
	"go.step.sm/crypto/kms"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/pemutil"

	"github.com/smallstep/step-kms-plugin/internal/flagutil"
)

// certificateCmd represents the certificate command
var certificateCmd = &cobra.Command{
	Use:   "certificate <uri>",
	Short: "print or import a certificate in a KMS",
	Long:  `This command, if the KMS supports it, prints or imports a certificate in a KMS.`,
	Example: `  # Import a certificate to a PKCS #11 module:
  step-kms-plugin certificate --import cert.pem \
  --kms 'pkcs11:module-path=/path/to/libsofthsm2.so;token=softhsm?pin-value=pass' \
  'pkcs11:id=2000;object=my-cert'

  # Print a previously stored certificate:
  step-kms-plugin certificate \
  --kms 'pkcs11:module-path=/path/to/libsofthsm2.so;token=softhsm?pin-value=pass' \
  'pkcs11:id=2000;object=my-cert'
  
  # Print a previously stored certificate for an Attestation Key (AK), using the default TPM KMS:
  step-kms-plugin certificate 'tpmkms:name=my-ak;ak=true'

  # Print a previously stored certificate, using the default TPM KMS:
  step-kms-plugin certificate tpmkms:name=my-key

  # Print a previously stored certificate chain, using the default TPM KMS:
  step-kms-plugin certificate --bundle tpmkms:name=my-key`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return showErrUsage(cmd)
		}

		name := args[0]
		flags := cmd.Flags()
		certFile := flagutil.MustString(flags, "import")
		bundle := flagutil.MustBool(flags, "bundle")

		kuri := ensureSchemePrefix(flagutil.MustString(flags, "kms"))
		if kuri == "" {
			kuri = name
		}

		// Read a certificate using the CertFS.
		if certFile == "" {
			fsys, err := kms.CertFS(cmd.Context(), kuri)
			if err != nil {
				return err
			}
			defer fsys.Close()

			b, err := fs.ReadFile(fsys, args[0]) // TODO: make this read the full chain?
			if err != nil {
				return err
			}

			fmt.Print(string(b))
			return nil
		}

		// Import and read certificate using the key manager to avoid opening the kms twice.
		var cert *x509.Certificate
		certs, err := pemutil.ReadCertificateBundle(certFile)
		if err != nil {
			return err
		}

		km, err := kms.New(cmd.Context(), apiv1.Options{
			URI: kuri,
		})
		if err != nil {
			return fmt.Errorf("failed to load key manager: %w", err)
		}
		defer km.Close()

		switch cm := km.(type) {
		case apiv1.CertificateChainManager:
			if err := cm.StoreCertificateChain(&apiv1.StoreCertificateChainRequest{
				Name:             name,
				CertificateChain: certs,
			}); err != nil {
				return err
			}
			certs, err = cm.LoadCertificateChain(&apiv1.LoadCertificateChainRequest{
				Name: name,
			})
			if err != nil {
				return err
			}
			cert = certs[0]
		case apiv1.CertificateManager:
			if err := cm.StoreCertificate(&apiv1.StoreCertificateRequest{
				Name:        name,
				Certificate: cert,
			}); err != nil {
				return err
			}
			cert, err = cm.LoadCertificate(&apiv1.LoadCertificateRequest{
				Name: name,
			})
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("%q does not implement a CertificateManager or CertificateChainManager", kuri)
		}

		switch {
		case bundle:
			for _, c := range certs {
				fmt.Print(string(pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: c.Raw,
				})))
			}
		default:
			fmt.Print(string(pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			})))
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(certificateCmd)
	certificateCmd.SilenceUsage = true

	flags := certificateCmd.Flags()
	flags.SortFlags = false

	flags.String("import", "", "The certificate `file` to import")
	flags.Bool("bundle", false, "Print all certificates in the chain/bundle")
}
