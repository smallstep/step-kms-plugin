/*
Copyright © 2022 Smallstep Labs, Inc.

*/
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
	Example: `  # Create an EC P-256 private key in a PKCS #11 module:
  step-kms-plugin create "pkcs11:module-path=/path/to/libsofthsm2.so;token=softhsm;id=1000?pin-value=pass"

  # Create an RSA key:
  step-kms-plugin create --kty RSA --size 4096 "pkcs11:module-path=/path/to/libsofthsm2.so;token=softhsm;id=1000?pin-value=pass"`,

	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return showUsageErr(cmd)
		}

		flags := cmd.Flags()
		kty := flagutil.MustString(flags, "kty")
		crv := flagutil.MustString(flags, "crv")
		size := flagutil.MustInt(flags, "size")
		hash := flagutil.MustString(flags, "hash")
		pss := flagutil.MustBool(flags, "pss")
		extractable := flagutil.MustBool(flags, "extractable")
		pl := flagutil.MustString(flags, "protection-level")

		signatureAlgorithm := getSignatureAlgorithm(kty, crv, hash, pss)
		if signatureAlgorithm == apiv1.UnspecifiedSignAlgorithm {
			return fmt.Errorf("failed to get a signature algorithm with kty: %q, crv: %q, hash: %q", kty, crv, hash)
		}

		protectionLevel := getProtectionLevel(pl)
		if protectionLevel == apiv1.UnspecifiedProtectionLevel {
			return fmt.Errorf("unsupported protection level: %q", pl)
		}

		kuri, _ := cmd.Flags().GetString("kms")
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
	hash string
	pss  bool
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

func getSignatureAlgorithm(kty, crv, hash string, pss bool) apiv1.SignatureAlgorithm {
	switch strings.ToUpper(kty) {
	case "EC":
		return ecSignatureAlgorithmMapping[ecParams{crv}]
	case "RSA":
		return rsaSignatureAlgorithmMapping[rsaParams{hash, pss}]
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

	flags := createCmd.Flags()
	flags.SortFlags = false

	kty := flagutil.UpperValue("kty", []string{"EC", "RSA", "OKP"}, "EC")
	crv := flagutil.NormalizedValue("crv", []string{"P256", "P384", "P521", "Ed25519"}, "P256")
	hash := flagutil.NormalizedValue("hash", []string{"SHA256", "SHA384", "SHA512"}, "SHA256")
	protectionLevel := flagutil.UpperValue("protection-level", []string{"SOFTWARE", "HSM"}, "SOFTWARE")

	flags.String("kms", "", "The `uri` with the kms configuration to use")
	flags.Var(kty, "kty", "The key `type` to build the certificate upon.\nOptions are EC, RSA or OKP")
	flags.Var(crv, "crv", "The elliptic `curve` to use for EC and OKP key types.\nOptions are P256, P384, P521 or Ed25519 on OKP")
	flags.Int("size", 3072, "The key size for an RSA key")
	flags.Var(hash, "hash", "The hashing `algorithm` used in the signature.\nOptions are SHA256, SHA384 or SHA512")
	flags.Var(protectionLevel, "protection-level", "The protection `level` used on some Cloud KMSs.\nOptions are SOFTWARE or HSM")
	flags.Bool("pss", false, "Use RSA-PSS signature scheme instead of PKCS #1")
	flags.Bool("extractable", false, "Mark the new key as extractable")
	flags.Bool("json", false, "Show the output using JSON")
}
