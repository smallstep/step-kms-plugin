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
	"fmt"
	"io/fs"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"go.step.sm/crypto/kms"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/uri"
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
  
  # Import a certificate for an Attestation Key (AK), using the default TPM KMS:
  step-kms-plugin certificate --import cert.pem 'tpmkms:name=my-ak;ak=true'

  # Import a certificate, using the default TPM KMS:
  step-kms-plugin certificate --import cert.pem tpmkms:name=my-key

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

		flags := cmd.Flags()
		certFile := flagutil.MustString(flags, "import")
		bundle := flagutil.MustBool(flags, "bundle")

		kuri, name, err := getURIAndNameForFS(flagutil.MustString(flags, "kms"), args[0])
		if err != nil {
			return err
		}

		// Read a certificate using the CertFS.
		if certFile == "" {
			if bundle {
				km, err := openKMS(cmd.Context(), kuri)
				if err != nil {
					return fmt.Errorf("failed to load key manager: %w", err)
				}
				defer km.Close()
				if cm, ok := km.(apiv1.CertificateChainManager); ok {
					certs, err := cm.LoadCertificateChain(&apiv1.LoadCertificateChainRequest{
						Name: name,
					})
					if err != nil {
						return err
					}
					for _, c := range certs {
						outputCert(c)
					}
					return nil
				}
				return fmt.Errorf("--bundle is not compatible with %q", kuri)
			}

			// TODO(hs): support reading a certificate chain / bundle instead of
			// just single certificate in the CertFS instead? Would require supporting
			// serializing multiple things to PEM, e.g. a certificate chain.
			fsys, err := kms.CertFS(cmd.Context(), kuri)
			if err != nil {
				return err
			}
			defer fsys.Close()

			b, err := fs.ReadFile(fsys, name)
			if err != nil {
				return err
			}

			fmt.Print(string(b))
			return nil
		}

		// Import and read certificate using the key manager to avoid opening the kms twice.
		certs, err := pemutil.ReadCertificateBundle(certFile)
		if err != nil {
			return err
		}
		if len(certs) == 0 {
			return fmt.Errorf("no certificates found in %q", certFile)
		}
		cert := certs[0]

		km, err := openKMS(cmd.Context(), kuri)
		if err != nil {
			return fmt.Errorf("failed to load key manager: %w", err)
		}
		defer km.Close()

		// On mackms there's no need to specify a label (name), the keychain
		// will automatically use the common name by default. But we always need
		// a label to load the certificate.
		loadCertificateName := name
		if strings.EqualFold(loadCertificateName, "mackms:") {
			loadCertificateName = uri.New("mackms", url.Values{
				"label": []string{cert.Subject.CommonName},
			}).String()
		}

		switch cm := km.(type) {
		case apiv1.CertificateChainManager:
			if err := cm.StoreCertificateChain(&apiv1.StoreCertificateChainRequest{
				Name:             name,
				CertificateChain: certs,
			}); err != nil {
				return err
			}
			certs, err = cm.LoadCertificateChain(&apiv1.LoadCertificateChainRequest{
				Name: loadCertificateName,
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
				Name: loadCertificateName,
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
				if err := outputCert(c); err != nil {
					return err
				}
			}
			return nil
		default:
			return outputCert(cert)
		}
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
