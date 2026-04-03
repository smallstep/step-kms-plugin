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
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/uri"
	"go.step.sm/crypto/pemutil"

	"github.com/smallstep/step-kms-plugin/internal/flagutil"
)

var certificateCopyCmd = &cobra.Command{
	Use:   "copy <src> <dst-uri>",
	Short: "copy a certificate into a KMS",
	Long: `Copies a certificate or a certificate chain into a KMS from a PEM file or another
KMS URI. If the destination KMS does not support certificate chains, only the leaf
certificate will be stored and printed.`,
	Example: `  # Copy a certificate from a file into a PKCS #11 module:
  step-kms-plugin certificate copy \
  --kms 'pkcs11:module-path=/path/to/libsofthsm2.so;token=softhsm?pin-value=pass' \
  cert.pem 'pkcs11:id=2000;object=my-cert'

  # Copy a certificate from a file into the default TPM KMS:
  step-kms-plugin certificate copy cert.pem tpmkms:name=my-key

  # Copy a certificate from a file for an Attestation Key (AK) into the default TPM KMS:
  step-kms-plugin certificate copy cert.pem 'tpmkms:name=my-ak;ak=true'

  # Copy a certificate from a YubiKey into the macOS Keychain:
  step-kms-plugin certificate copy 'yubikey:slot-id=9c' mackms:label=my-cert`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 2 {
			return showErrUsage(cmd)
		}

		// Load certificates from a file or a source KMS URI.
		var (
			certs  []*x509.Certificate
			srcArg = args[0]
		)

		if _, typeErr := apiv1.TypeOf(srcArg); typeErr == nil {
			srcKuri, srcName, err := getURIAndNameForFS("", srcArg)
			if err != nil {
				return err
			}

			srcKM, err := openKMS(cmd.Context(), srcKuri)
			if err != nil {
				return fmt.Errorf("failed to load source key manager: %w", err)
			}
			defer srcKM.Close()

			switch cm := srcKM.(type) {
			case apiv1.CertificateChainManager:
				certs, err = cm.LoadCertificateChain(&apiv1.LoadCertificateChainRequest{
					Name: srcName,
				})
			case apiv1.CertificateManager:
				c, err := cm.LoadCertificate(&apiv1.LoadCertificateRequest{
					Name: srcName,
				})
				if err != nil {
					return err
				}
				certs = []*x509.Certificate{c}
			default:
				return fmt.Errorf("%q does not implement a CertificateManager or CertificateChainManager", srcArg)
			}
			if err != nil {
				return err
			}
		} else {
			var err error
			certs, err = pemutil.ReadCertificateBundle(srcArg)
			if err != nil {
				return err
			}
		}
		if len(certs) == 0 {
			return fmt.Errorf("no certificates found in %q", srcArg)
		}

		kuri, name, err := getURIAndNameForFS(flagutil.MustString(cmd.Flags(), "kms"), args[1])
		if err != nil {
			return err
		}

		km, err := openKMS(cmd.Context(), kuri)
		if err != nil {
			return fmt.Errorf("failed to load key manager: %w", err)
		}
		defer km.Close()

		// On mackms there's no need to specify a label (name), the keychain
		// will automatically use the common name by default. But we always need
		// a label to load the certificate.
		var (
			leaf                = certs[0]
			loadCertificateName = name
		)
		if strings.EqualFold(loadCertificateName, "mackms:") {
			loadCertificateName = uri.New("mackms", url.Values{
				"label": []string{leaf.Subject.CommonName},
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
			leaf = certs[0]
		case apiv1.CertificateManager:
			if err := cm.StoreCertificate(&apiv1.StoreCertificateRequest{
				Name:        name,
				Certificate: leaf,
			}); err != nil {
				return err
			}
			leaf, err = cm.LoadCertificate(&apiv1.LoadCertificateRequest{
				Name: loadCertificateName,
			})
			if err != nil {
				return err
			}
			if len(certs) > 1 {
				certs = []*x509.Certificate{leaf}
			}
		default:
			return fmt.Errorf("%q does not implement a CertificateManager or CertificateChainManager", kuri)
		}

		for _, c := range certs {
			if err := outputCert(c); err != nil {
				return err
			}
		}

		return nil
	},
}

func init() {
	certificateCmd.AddCommand(certificateCopyCmd)
	certificateCopyCmd.SilenceUsage = true
}
