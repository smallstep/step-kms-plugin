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

	"github.com/spf13/cobra"
	"go.step.sm/crypto/kms"
)

// certificateCmd represents the certificate command
var certificateCmd = &cobra.Command{
	Use:   "certificate <uri>",
	Short: "print a certificate in a kms",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return showUsageErr(cmd)
		}

		kuri, _ := cmd.Flags().GetString("kms")
		if kuri == "" {
			kuri = args[0]
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

	certificateCmd.Flags().String("kms", "", "Uri with the kms configuration to use")
}
