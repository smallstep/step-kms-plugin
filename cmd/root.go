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
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"go.step.sm/cli-utils/step"
	"go.step.sm/crypto/kms"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/uri"
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

// openKMS is a helper on top of kms.New that can set custom options depending
// on the KMS type.
func openKMS(ctx context.Context, kuri string) (apiv1.KeyManager, error) {
	typ, err := apiv1.TypeOf(kuri)
	if err != nil {
		return nil, err
	}

	var storageDirectory string
	if typ == apiv1.TPMKMS {
		if err := step.Init(); err != nil {
			return nil, err
		}
		storageDirectory = filepath.Join(step.Path(), "tpm")
	}

	// Type is not necessary, but it avoids an extra validation
	return kms.New(ctx, apiv1.Options{
		Type:             typ,
		URI:              kuri,
		StorageDirectory: storageDirectory,
	})
}

// changeURI adds extra parameters to the given uri.
//
// If the given values are already in the rawuri, the new values will take
// preference.
func changeURI(rawuri string, values url.Values) (string, error) {
	u, err := uri.Parse(rawuri)
	if err != nil {
		return "", err
	}

	// Modify RawQuery with the given values
	v := u.Query()
	for k, vs := range values {
		for _, vv := range vs {
			v.Add(k, vv)
		}
	}
	u.RawQuery = v.Encode()

	return u.String(), nil
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

// getURIAndNameForFS returns the kuri and name to be used by a KMS FS. If TPM
// KMS is used, it changes the kuri to add the default storage directory.
//
// If a storage-directory is already in the kuri, this will take preference.
func getURIAndNameForFS(kuri, name string) (string, string, error) {
	kuri = ensureSchemePrefix(kuri)
	if kuri == "" {
		kuri = name
	}

	typ, err := apiv1.TypeOf(kuri)
	if err != nil {
		return "", "", err
	}

	if typ == apiv1.TPMKMS {
		if err := step.Init(); err != nil {
			return "", "", err
		}
		kuri, err = changeURI(kuri, url.Values{"storage-directory": []string{filepath.Join(step.Path(), "tpm")}})
		if err != nil {
			return "", "", err
		}
	}

	return kuri, name, nil
}

// outputCert encodes an X.509 certificate to PEM format
// and writes it to stdout.
func outputCert(c *x509.Certificate) error {
	if err := pem.Encode(os.Stdout, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.Raw,
	}); err != nil {
		return fmt.Errorf("failed to encode certificate: %w", err)
	}
	return nil
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
