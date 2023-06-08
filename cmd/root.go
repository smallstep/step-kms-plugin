// Copyright 2022 Smallstep Labs, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"go.step.sm/crypto/pemutil"

	"github.com/smallstep/step-kms-plugin/internal/termutil"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "step-kms-plugin",
	Short: "step plugin to manage KMSs",
	Long: `step-kms-plugin is a plugin for step that allows performing cryptographic
operations on Hardware Security Modules (HSMs), Cloud Key Management Services
(KMSs) and devices like YubiKey that implement a Personal Identity Verification (PIV)
interface. This command uses the term KMS to refer to any of these interfaces.

step-kms-plugin can be used using 'step kms [command]', or as a standalone
application.

Common operations include:
 - Create asymmetric key pair on a KMS
 - Sign data using an existing KMS-stored key
 - Extract public keys and certificates stored in a KMS`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

var errUsage = errors.New("usage")

func showErrUsage(cmd *cobra.Command) error {
	cmd.SilenceErrors = true
	cmd.SilenceUsage = false
	return errUsage
}

// ensureSchemePrefix checks if a (non-empty) KMS URI contains a
// colon, indicating it contains a potentially valid KMS scheme.
// If the KMS URI doesn't start with a scheme, the colon is suffixed.
// This allows users to provide '--kms tpmkms' instead of requiring
// '--kms tpmkms:', which results in a potentially confusing error
// message.
func ensureSchemePrefix(kuri string) string {
	if kuri != "" && !strings.Contains(kuri, ":") {
		kuri = fmt.Sprintf("%s:", kuri)
	}
	return kuri
}

func init() {
	flags := rootCmd.PersistentFlags()
	flags.String("kms", "", "The `uri` with the kms configuration to use")

	// Define a password reader
	pemutil.PromptPassword = func(s string) ([]byte, error) {
		if s[len(s)-1] != ':' {
			s += ":"
		}
		return termutil.ReadPassword(s)
	}
}
