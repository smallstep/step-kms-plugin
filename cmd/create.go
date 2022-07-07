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
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/smallstep/step-kms-plugin/internal/flagutil"
	"github.com/spf13/cobra"
	"go.step.sm/crypto/kms"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/pemutil"
)

// createCmd represents the create command
var createCmd = &cobra.Command{
	Use:   "create <uri>",
	Short: "generates a key in the KMS",
	Long: `Creates a private key in the KMS and prints its public key.

This command allows the creation of new asymmetric keys on the KMS. By default,
it creates an EC P-256 key, but the --kty, --crv and --size flags can be
combined to create a different type of key. RSA and EC keys are generally
supported by all the KMS, but Ed25519 (OKP) support is currently very limited.

For keys in the AWS KMS is recommended to use the JSON output as we need the
generated key-id to access it.

Keys in a PKCS #11 module requires an id in hexadecimal as well as a label
(e.g. pkcs11:id=10ab;object=my-label).`,
	Example: `  # Create an EC P-256 private key in a PKCS #11 module:
  step-kms-plugin create \
  'pkcs11:module-path=/path/to/libsofthsm2.so;token=softhsm;id=1000;object=my-key?pin-value=pass'

  # Create an EC P-384 private key in a PKCS #11 module:
  step-kms-plugin create --kty EC --crv P-384 \
  --kms 'pkcs11:module-path=/path/to/libsofthsm2.so;token=softhsm?pin-source=/var/run/pass.txt' \
  'pkcs11:id=1000;object=my-key'

  # Create an 3072 bit RSA key in a PKCS#11 module:
  step-kms-plugin create --kty RSA \
  --kms 'pkcs11:module-path=/path/to/libsofthsm2.so;token=softhsm?pin-value=pass' \
  'pkcs11:id=1000;object=my-rsa-key'

  # Create a 4096 bit RSA-PSS key on Google's Cloud KMS with a credentials file:
  step-kms-plugin create --kty RSA --size 4096 --pss \
  --kms cloudkms:credentials-file=kms-credentials.json \
  projects/my-project/locations/us-west1/keyRings/my-keyring/cryptoKeys/my-rsa-key

  # Create a key on Google's Cloud KMS using gcloud credentials:
  step-kms-plugin create --kms cloudkms: \
  projects/my-project/locations/us-west1/keyRings/my-keyring/cryptoKeys/my-ec-key

  # Create a key on Azure's Key Vault using az credentials:
  step-kms-plugin create 'azurekms:vault=my-key-vault;name=my-key'

  # Create a key on AWS KMS with the name tag my-key, but return the value in JSON so we can get the key-id to access it.
  step-kms-plugin create --json --kms awskms:region=us-west-2 my-key

  # Create an 2048 bit RSA key on a YubiKey:
  step-kms-plugin create --kty RSA --size 2048 yubikey:slot-id=82`,

	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return showUsageErr(cmd)
		}

		flags := cmd.Flags()

		kty := flagutil.MustString(flags, "kty")
		crv := flagutil.MustString(flags, "crv")
		size := flagutil.MustInt(flags, "size")
		alg := flagutil.MustString(flags, "alg")
		pss := flagutil.MustBool(flags, "pss")
		extractable := flagutil.MustBool(flags, "extractable")
		pl := flagutil.MustString(flags, "protection-level")

		if kty != "RSA" {
			size = 0
		}
		// Do not set crv unless the flag is explicitly set by the user
		if kty != "EC" && !flags.Changed("crv") {
			crv = ""
		}

		signatureAlgorithm := getSignatureAlgorithm(kty, crv, alg, pss)
		if signatureAlgorithm == apiv1.UnspecifiedSignAlgorithm {
			return fmt.Errorf("failed to get a signature algorithm with kty: %q, crv: %q, hash: %q", kty, crv, alg)
		}

		protectionLevel := getProtectionLevel(pl)
		if protectionLevel == apiv1.UnspecifiedProtectionLevel {
			return fmt.Errorf("unsupported protection level: %q", pl)
		}

		kuri := flagutil.MustString(flags, "kms")
		if kuri == "" {
			kuri = args[0]
		}

		cmd.SilenceUsage = true
		km, err := kms.New(context.Background(), apiv1.Options{
			URI: kuri,
		})
		if err != nil {
			return fmt.Errorf("failed to load key manager: %w", err)
		}
		defer km.Close()

		resp, err := km.CreateKey(&apiv1.CreateKeyRequest{
			Name:               args[0],
			SignatureAlgorithm: signatureAlgorithm,
			Bits:               size,
			ProtectionLevel:    protectionLevel,
			Extractable:        extractable,
		})
		if err != nil {
			return fmt.Errorf("failed to create key: %w", err)
		}

		block, err := pemutil.Serialize(resp.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to serialize public key: %w", err)
		}

		if flagutil.MustBool(flags, "json") {
			b, err := json.MarshalIndent(map[string]string{
				"name":      resp.Name,
				"publicKey": string(pem.EncodeToMemory(block)),
			}, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal: %w", err)
			}
			fmt.Println(string(b))
		} else {
			fmt.Print(string(pem.EncodeToMemory(block)))
		}
		return nil
	},
}

type rsaParams struct {
	alg string
	pss bool
}

var rsaSignatureAlgorithmMapping = map[rsaParams]apiv1.SignatureAlgorithm{
	{"", false}:       apiv1.SHA256WithRSA,
	{"SHA256", false}: apiv1.SHA256WithRSA,
	{"SHA384", false}: apiv1.SHA384WithRSA,
	{"SHA512", false}: apiv1.SHA512WithRSA,
	{"SHA256", true}:  apiv1.SHA256WithRSAPSS,
	{"SHA384", true}:  apiv1.SHA384WithRSAPSS,
	{"SHA512", true}:  apiv1.SHA512WithRSAPSS,
}

type ecParams struct {
	crv string
}

var ecSignatureAlgorithmMapping = map[ecParams]apiv1.SignatureAlgorithm{
	{""}:     apiv1.ECDSAWithSHA256,
	{"P256"}: apiv1.ECDSAWithSHA256,
	{"P384"}: apiv1.ECDSAWithSHA384,
	{"P521"}: apiv1.ECDSAWithSHA512,
}

type okpParams struct {
	crv string
}

var okpSignatureAlgorithmMapping = map[okpParams]apiv1.SignatureAlgorithm{
	{""}:        apiv1.PureEd25519,
	{"ED25519"}: apiv1.PureEd25519,
}

func getSignatureAlgorithm(kty, crv, alg string, pss bool) apiv1.SignatureAlgorithm {
	switch strings.ToUpper(kty) {
	case "EC":
		return ecSignatureAlgorithmMapping[ecParams{crv}]
	case "RSA":
		return rsaSignatureAlgorithmMapping[rsaParams{alg, pss}]
	case "OKP":
		return okpSignatureAlgorithmMapping[okpParams{crv}]
	default:
		return ecSignatureAlgorithmMapping[ecParams{crv}]
	}
}

func getProtectionLevel(pl string) apiv1.ProtectionLevel {
	switch strings.ToUpper(pl) {
	case "", "SOFTWARE":
		return apiv1.Software
	case "HSM", "HARDWARE":
		return apiv1.HSM
	default:
		return apiv1.UnspecifiedProtectionLevel
	}
}

func init() {
	rootCmd.AddCommand(createCmd)
	createCmd.SilenceUsage = true

	flags := createCmd.Flags()
	flags.SortFlags = false

	kty := flagutil.UpperValue("kty", []string{"EC", "RSA", "OKP"}, "EC")
	crv := flagutil.NormalizedValue("crv", []string{"P256", "P384", "P521", "Ed25519"}, "P256")
	alg := flagutil.NormalizedValue("alg", []string{"SHA256", "SHA384", "SHA512"}, "SHA256")
	protectionLevel := flagutil.UpperValue("protection-level", []string{"SOFTWARE", "HSM"}, "SOFTWARE")

	flags.Var(kty, "kty", "The key `type` to build the certificate upon.\nOptions are EC, RSA or OKP")
	flags.Var(crv, "crv", "The elliptic `curve` to use for EC and OKP key types.\nOptions are P256, P384, P521 or Ed25519 on OKP")
	flags.Int("size", 3072, "The key size for an RSA key")
	flags.Var(alg, "alg", "The hashing `algorithm` to use on RSA PKCS #1 and RSA-PSS signatures.\nOptions are SHA256, SHA384 or SHA512")
	flags.Var(protectionLevel, "protection-level", "The protection `level` used on some Cloud KMSs.\nOptions are SOFTWARE or HSM")
	flags.Bool("pss", false, "Use RSA-PSS signature scheme instead of PKCS #1")
	flags.Bool("extractable", false, "Mark the new key as extractable")
	flags.Bool("json", false, "Show the output using JSON")
}
