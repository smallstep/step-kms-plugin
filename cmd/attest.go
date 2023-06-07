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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/fxamacker/cbor/v2"
	"github.com/spf13/cobra"
	"go.step.sm/crypto/kms"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/pemutil"

	"github.com/smallstep/step-kms-plugin/internal/flagutil"
)

// attestCmd represents the attest command
var attestCmd = &cobra.Command{
	Use:   "attest <uri>",
	Short: "create an attestation certificate",
	Long: `Print an attestation certificate, an endorsement key, or if the "--format" flag
is set, an attestation object. Currently this command is only supported on
YubiKeys.

An attestation object can be used to resolve an ACME device-attest-01 challenge.
To pass this challenge, the client needs proof of possession of a private key by
signing the ACME key authorization. The format is defined in RFC 8555 as a
string that concatenates the challenge token for the challenge with the ACME
account key fingerprint separated by a "." character:

  keyAuthorization = token || '.' || base64url(Thumbprint(accountKey))`,
	Example: `  # Get the attestation certificate from a YubiKey:
  step-kms-plugin attest yubikey:slot-id=9c

  # Create an attestation object used in an ACME device-attest-01 flow:
  echo -n <token>.<fingerprint> | step-kms-plugin attest --format step yubikey:slot-id=9c`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return showErrUsage(cmd)
		}

		name := args[0]
		flags := cmd.Flags()
		format := flagutil.MustString(flags, "format")
		in := flagutil.MustString(flags, "in")
		kuri := flagutil.MustString(flags, "kms")
		if kuri == "" {
			kuri = name
		}

		km, err := kms.New(cmd.Context(), apiv1.Options{
			URI: kuri,
		})
		if err != nil {
			return fmt.Errorf("failed to load key manager: %w", err)
		}
		defer km.Close()

		attester, ok := km.(apiv1.Attester)
		if !ok {
			return fmt.Errorf("%s does not implement Attester", kuri)
		}

		resp, err := attester.CreateAttestation(&apiv1.CreateAttestationRequest{
			Name: name,
		})
		if err != nil {
			return fmt.Errorf("failed to attest: %w", err)
		}

		switch {
		case format != "":
			var data []byte
			if format != "tpm" { // the tpm format doesn't require data to be signed
				data, err = getAttestationData(in)
				if err != nil {
					return err
				}
			}
			signer, err := km.CreateSigner(&apiv1.CreateSignerRequest{
				SigningKey: name,
			})
			if err != nil {
				return fmt.Errorf("failed to get a signer: %w", err)
			}
			var certs []*x509.Certificate
			switch {
			case len(resp.CertificateChain) > 0:
				certs = resp.CertificateChain
			case resp.Certificate != nil:
				certs = []*x509.Certificate{resp.Certificate}
			}
			return printAttestationObject(format, certs, signer, data, resp.CertificationParameters)
		case len(resp.CertificateChain) > 0:
			for _, c := range resp.CertificateChain {
				if err := pem.Encode(os.Stdout, &pem.Block{
					Type:  "CERTIFICATE",
					Bytes: c.Raw,
				}); err != nil {
					return fmt.Errorf("failed to encode certificate chain: %w", err)
				}
			}
			return nil
		case resp.Certificate != nil:
			if err := pem.Encode(os.Stdout, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: resp.Certificate.Raw,
			}); err != nil {
				return fmt.Errorf("failed to encode certificate: %w", err)
			}
			return nil
		case resp.PublicKey != nil:
			block, err := pemutil.Serialize(resp.PublicKey)
			if err != nil {
				return err
			}
			return pem.Encode(os.Stdout, block)
		default:
			return errors.New("failed to create attestation: unsupported response")
		}
	},
}

type attestationObject struct {
	Format       string                 `json:"fmt"`
	AttStatement map[string]interface{} `json:"attStmt,omitempty"`
}

func getAttestationData(in string) ([]byte, error) {
	if in != "" {
		return os.ReadFile(in)
	}
	fi, err := os.Stdin.Stat()
	if err != nil {
		return nil, err
	}
	if (fi.Mode() & os.ModeCharDevice) == 0 {
		return io.ReadAll(os.Stdin)
	}
	fmt.Println("Type data to sign and press Ctrl+D to finish:")
	return io.ReadAll(os.Stdin)
}

func printAttestationObject(format string, certs []*x509.Certificate, signer crypto.Signer, data []byte, params *apiv1.CertificationParameters) error {
	var alg int64
	var digest []byte
	var opts crypto.SignerOpts
	switch k := signer.Public().(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return fmt.Errorf("unsupported elliptic curve %s", k.Curve)
		}
		alg = -7 // ES256
		opts = crypto.SHA256
		sum := sha256.Sum256(data)
		digest = sum[:]
	case *rsa.PublicKey:
		// TODO(mariano): support for PS256 (-37)
		alg = -257 // RS256
		opts = crypto.SHA256
		sum := sha256.Sum256(data)
		digest = sum[:]
	case ed25519.PublicKey:
		alg = -8 // EdDSA
		opts = crypto.Hash(0)
		digest = data
	default:
		return fmt.Errorf("unsupported public key type %T", k)
	}

	stmt := map[string]interface{}{
		"alg": alg,
	}

	switch format {
	case "tpm":
		// TPM key attestation is performed at key creation time. The key is attested by
		// an Attestation Key (AK). The result of attesting a key can be recorded, so that
		// the certification facts can be used at a later time to verify the key was created
		// by a specific TPM.
		if params == nil {
			return errors.New("TPM key attestation requires CertificationParameters to be set")
		}
		stmt["ver"] = "2.0"
		stmt["sig"] = params.CreateSignature // signature over the (empty) data is ignored for the tpm format
		stmt["certInfo"] = params.CreateAttestation
		stmt["pubArea"] = params.Public
	default:
		// Sign proves possession of private key. Per recommendation at
		// https://w3c.github.io/webauthn/#sctn-signature-attestation-types, we use
		// CBOR to encode the signature.
		sig, err := signer.Sign(rand.Reader, digest, opts)
		if err != nil {
			return fmt.Errorf("failed to sign key authorization: %w", err)
		}
		sig, err = cbor.Marshal(sig)
		if err != nil {
			return fmt.Errorf("failed marshaling signature: %w", err)
		}
		stmt["sig"] = sig
	}

	if len(certs) > 0 {
		x5c := make([][]byte, len(certs))
		for i, c := range certs {
			x5c[i] = c.Raw
		}
		stmt["x5c"] = x5c
	}

	obj := attestationObject{
		Format:       format,
		AttStatement: stmt,
	}

	b, err := cbor.Marshal(obj)
	if err != nil {
		return fmt.Errorf("failed marshaling attestation object: %w", err)
	}

	fmt.Println(base64.RawURLEncoding.EncodeToString(b))
	return nil
}

func init() {
	rootCmd.AddCommand(attestCmd)
	attestCmd.SilenceUsage = true

	flags := attestCmd.Flags()
	flags.SortFlags = false

	format := flagutil.LowerValue("format", []string{"", "step", "packed", "tpm"}, "")
	flags.Var(format, "format", "The `format` to print the attestation.\nOptions are step, packed or tpm")
	flags.String("in", "", "The `file` to sign with an attestation format.")
}
