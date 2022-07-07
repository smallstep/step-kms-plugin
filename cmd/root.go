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
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "step-kms-plugin",
	Short: "step plugin to manage KMSs",
	Long: `step-kms-plugin is a plugin for step that allows performing cryptographic
operations on Hardware Security Modules (HSMs), Cloud Key Management Services
(KMSs) and devices like YubiKey using the Personal Identity Verification (PIV)
interface. This command will always use the term KSM independently of the
interface used.

step-kms-plugin can be used using 'step kms [command]' or as a standalone
application.

Common operations of step-kms-plugin include:
 - Create asymmetric keys.
 - Sign data using an existing key.
 - Extract public keys and certificates stored in a KMS.

For development purposes, on macOS and Linux, step-kms-plugin automatically
configures the KMS to use softhsm2 with the token smallstep.

To initialize the token, run:
  softhsm2-util --init-token --free --token smallstep \
  --label smallstep --so-pin password --pin password

To delete it, run:
  softhsm2-util --delete-token --token smallstep`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

var usageErr = errors.New("usage")

func showUsageErr(cmd *cobra.Command) error {
	cmd.SilenceErrors = true
	cmd.SilenceUsage = false
	return usageErr
}

func init() {
	flags := rootCmd.PersistentFlags()
	var path string
	switch runtime.GOOS {
	case "darwin":
		if runtime.GOARCH == "arm64" {
			path = "/opt/homebrew/lib/softhsm/libsofthsm2.so"
		} else {
			path = "/usr/local/lib/softhsm/libsofthsm2.so"
		}
	case "linux":
		path = "/usr/lib/softhsm/libsofthsm2.so"
	}

	var kms string
	if path != "" {
		if _, err := os.Stat(path); err == nil {
			kms = fmt.Sprintf("pkcs11:module-path=%s;token=smallstep?pin-value=password", path)
		}
	}
	flags.String("kms", kms, "The `uri` with the kms configuration to use")
}
