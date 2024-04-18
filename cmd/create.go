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
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/softkms"
	"go.step.sm/crypto/kms/tpmkms"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/tpm/tss2"

	"github.com/smallstep/step-kms-plugin/internal/flagutil"
	"github.com/smallstep/step-kms-plugin/internal/termutil"
)

// createCmd represents the create command
var createCmd = &cobra.Command{
	Use:   "create <uri>",
	Short: "generates a key pair in the KMS",
	Long: `Creates a private key in the KMS and prints its public key.

This command creates a new asymmetric key pair on the KMS. By default,
it creates an EC P-256 key, but the --kty, --crv and --size flags can be
combined to adjust the key properties. RSA and EC keys are broadly
supported, but as of 2023 Ed25519 (OKP) support is very limited.

For keys in AWS KMS, we recommend using --json for output, as you will need the
generated key-id.

Keys in a PKCS #11 module requires an id in hexadecimal as well as a label
(e.g. pkcs11:id=10ab;object=my-label).`,
	Example: `  # Create an EC P-256 private key in a PKCS #11 module:
  step-kms-plugin create \
  'pkcs11:module-path=/path/to/libsofthsm2.so;token=softhsm;id=1000;object=my-key?pin-value=pass'

  # Create an EC P-384 private key in a PKCS #11 module:
  step-kms-plugin create --kty EC --crv P-384 \
  --kms 'pkcs11:module-path=/path/to/libsofthsm2.so;token=softhsm?pin-source=/var/run/pass.txt' \
  'pkcs11:id=1000;object=my-key'

  # Create an 3072-bit RSA key in a PKCS#11 module:
  step-kms-plugin create --kty RSA \
  --kms 'pkcs11:module-path=/path/to/libsofthsm2.so;token=softhsm?pin-value=pass' \
  'pkcs11:id=1000;object=my-rsa-key'

  # Create a key on Google's Cloud KMS using gcloud credentials:
  step-kms-plugin create cloudkms:projects/my-project/locations/us-west1/keyRings/my-keyring/cryptoKeys/my-ec-key

  # Create a 4096-bit RSA-PSS key on Google's Cloud KMS with a credentials file:
  step-kms-plugin create --kty RSA --size 4096 --pss \
  --kms cloudkms:credentials-file=kms-credentials.json \
  projects/my-project/locations/us-west1/keyRings/my-keyring/cryptoKeys/my-rsa-key

  # Create a key on Azure's Key Vault using az credentials:
  step-kms-plugin create 'azurekms:vault=my-key-vault;name=my-key'

  # Create a key on AWS KMS with the name tag my-key. Return the value in JSON to get the uri used to access the key:
  step-kms-plugin create --json awskms:name=my-key

  # Create a 2048-bit RSA key on a YubiKey:
  step-kms-plugin create --kty RSA --size 2048 yubikey:slot-id=82

  # Create an EC P-256 private key on a YubiKey with the touch policy "always" and pin policy "once":
  step-kms-plugin create --touch-policy always --pin-policy once yubikey:slot-id=82

  # Create an Attestation Key (AK) in the default TPM KMS:
  step-kms-plugin create --kty RSA --size 2048 'tpmkms:name=my-ak;ak=true'

  # Create an EC P-256 private key in the default TPM KMS and print it using the TSS2 PEM format:
  step-kms-plugin create --format TSS2 tpmkms:name=my-ec-key

  # Create an EC P-256 private key in the TPM KMS, backed by /tmp/tpmobjects:
  step-kms-plugin create my-tmp-ec-key --kms tpmkms:storage-directory=/tmp/tpmobjects

  # Create an RSA 4096 bits private key in the default TPM KMS:
  step-kms-plugin create --kty RSA --size 4096 tpmkms:name=my-rsa-key

  # Create an EC P-256 private key, attested by an AK, in the default TPM KMS:
  step-kms-plugin create 'tpmkms:name=my-ec-key;attest-by=my-ak'`,

	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return showErrUsage(cmd)
		}

		flags := cmd.Flags()
		name := args[0]
		kty := flagutil.MustString(flags, "kty")
		crv := flagutil.MustString(flags, "crv")
		size := flagutil.MustInt(flags, "size")
		alg := flagutil.MustString(flags, "alg")
		pss := flagutil.MustBool(flags, "pss")
		extractable := flagutil.MustBool(flags, "extractable")
		pl := flagutil.MustString(flags, "protection-level")
		pinPolicy := pinPolicyMapping[flagutil.MustString(flags, "pin-policy")]
		touchPolicy := touchPolicyMapping[flagutil.MustString(flags, "touch-policy")]

		// Do not set crv unless the flag is explicitly set by the user
		if kty != "EC" && !flags.Changed("crv") {
			crv = ""
		}
		// Set kty RSA if the pss flag is passed
		if pss {
			if !flags.Changed("kty") {
				kty = "RSA"
			} else if kty != "RSA" {
				return fmt.Errorf("flag --pss is incompatible with --kty %s", kty)
			}
		}
		// Set the size to 0 for non-RSA keys
		if kty != "RSA" {
			size = 0
		}

		signatureAlgorithm := getSignatureAlgorithm(kty, crv, alg, pss)
		if signatureAlgorithm == apiv1.UnspecifiedSignAlgorithm {
			return fmt.Errorf("failed to get a signature algorithm with kty: %q, crv: %q, hash: %q", kty, crv, alg)
		}

		protectionLevel := getProtectionLevel(pl)
		if protectionLevel == apiv1.UnspecifiedProtectionLevel {
			return fmt.Errorf("unsupported protection level %q", pl)
		}

		kuri := ensureSchemePrefix(flagutil.MustString(flags, "kms"))
		if kuri == "" {
			kuri = name
		}

		cmd.SilenceUsage = true
		km, err := openKMS(cmd.Context(), kuri)
		if err != nil {
			return fmt.Errorf("failed to load key manager: %w", err)
		}
		defer km.Close()

		if _, ok := km.(*tpmkms.TPMKMS); ok {
			if flagutil.MustString(flags, "format") == "TSS2" {
				name, err = changeURI(name, url.Values{"tss2": []string{"true"}})
				if err != nil {
					return fmt.Errorf("failed to parse %q: %w", name, err)
				}
			}
		}

		resp, err := km.CreateKey(&apiv1.CreateKeyRequest{
			Name:               name,
			SignatureAlgorithm: signatureAlgorithm,
			Bits:               size,
			ProtectionLevel:    protectionLevel,
			Extractable:        extractable,
			PINPolicy:          pinPolicy,
			TouchPolicy:        touchPolicy,
		})
		if err != nil {
			return fmt.Errorf("failed to create key: %w", err)
		}

		// Store the private key on disk if softkms is used
		_, isSoftKMS := km.(*softkms.SoftKMS)
		if isSoftKMS && resp.PrivateKey != nil {
			block, err := pemutil.Serialize(resp.PrivateKey)
			if err != nil {
				return fmt.Errorf("failed to serialize the private key: %w", err)
			}
			if err := termutil.WriteFile(resp.Name, pem.EncodeToMemory(block), 0600); err != nil {
				return fmt.Errorf("failed to write the private key: %w", err)
			}
		}

		return printCreateKeyResponse(cmd, resp)
	},
}

func printCreateKeyResponse(cmd *cobra.Command, resp *apiv1.CreateKeyResponse) error {
	var (
		s            string
		isPrivateKey bool
		flags        = cmd.Flags()
	)

	switch flagutil.MustString(flags, "format") {
	case "PKCS1":
		if key, ok := resp.PublicKey.(*rsa.PublicKey); ok {
			s = string(pem.EncodeToMemory(&pem.Block{
				Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(key),
			}))
		}
	case "TSS2":
		if key, ok := resp.PrivateKey.(*tss2.TPMKey); ok {
			b, err := key.EncodeToMemory()
			if err != nil {
				return fmt.Errorf("failed to serialize the private key: %w", err)
			}
			s = string(b)
			isPrivateKey = true
		}
	}

	// Encode public key using PKIX format
	if s == "" {
		block, err := pemutil.Serialize(resp.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to serialize the public key: %w", err)
		}
		s = string(pem.EncodeToMemory(block))
	}

	if flagutil.MustBool(flags, "json") {
		m := map[string]string{
			"name": resp.Name,
		}
		if isPrivateKey {
			m["privateKey"] = s
		} else {
			m["publicKey"] = s
		}

		b, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal: %w", err)
		}
		fmt.Println(string(b))
	} else {
		fmt.Print(s)
	}

	return nil
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

var pinPolicyMapping = map[string]apiv1.PINPolicy{
	"":       0, // Use default on YubiKey kms (always)
	"NEVER":  apiv1.PINPolicyNever,
	"ALWAYS": apiv1.PINPolicyAlways,
	"ONCE":   apiv1.PINPolicyOnce,
}

var touchPolicyMapping = map[string]apiv1.TouchPolicy{
	"":       0, // Use default on YubiKey kms (never)
	"NEVER":  apiv1.TouchPolicyNever,
	"ALWAYS": apiv1.TouchPolicyAlways,
	"CACHED": apiv1.TouchPolicyCached,
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
	format := flagutil.NormalizedValue("format", []string{"PKIX", "PKCS1", "TSS2"}, "PKIX")
	protectionLevel := flagutil.UpperValue("protection-level", []string{"SOFTWARE", "HSM"}, "SOFTWARE")
	pinPolicy := flagutil.UpperValue("pin-policy", []string{"NEVER", "ALWAYS", "ONCE"}, "")
	touchPolicy := flagutil.UpperValue("touch-policy", []string{"NEVER", "ALWAYS", "CACHED"}, "")

	flags.Var(kty, "kty", "The key `type` to build the certificate upon.\nOptions are EC, RSA or OKP")
	flags.Var(crv, "crv", "The elliptic `curve` to use for EC and OKP key types.\nOptions are P256, P384, P521 or Ed25519 on OKP")
	flags.Int("size", 3072, "The key size for an RSA key")
	flags.Var(alg, "alg", "The hashing `algorithm` to use on RSA PKCS #1 and RSA-PSS signatures.\nOptions are SHA256, SHA384 or SHA512")
	flags.Var(protectionLevel, "protection-level", "The protection `level` used on some Cloud KMSs.\nOptions are SOFTWARE or HSM")
	flags.Var(pinPolicy, "pin-policy", "The pin `policy` used on YubiKey KMS.\nOptions are NEVER, ALWAYS or ONCE")
	flags.Var(touchPolicy, "touch-policy", "The touch `policy` used on YubiKey KMS.\nOptions are NEVER, ALWAYS or CACHED")
	flags.Bool("pss", false, "Use RSA-PSS signature scheme instead of PKCS #1")
	flags.Bool("extractable", false, "Mark the new key as extractable")
	flags.Var(format, "format", "The `format` to use in the output.\nOptions are PKIX, PKCS1 or TSS2")
	flags.Bool("json", false, "Show the output using JSON")
}
