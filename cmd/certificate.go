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
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/pemutil"
)

// certificateCmd represents the certificate command
var certificateCmd = &cobra.Command{
	Use:   "certificate <uri>",
	Short: "print a certificate in a kms",
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

		if certFile != "" {
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
		}

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
	},
}

func init() {
	rootCmd.AddCommand(certificateCmd)
	certificateCmd.SilenceUsage = true

	flags := certificateCmd.Flags()
	flags.SortFlags = false

	flags.String("import", "", "The certificate `file` to import")
}
