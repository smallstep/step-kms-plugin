package cmd

import (
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/smallstep/step-kms-plugin/internal/flagutil"
	"github.com/spf13/cobra"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/pemutil"
)

var searchCmd = &cobra.Command{
	Use:   "search <kms-uri>",
	Short: "search for keys stored in a KMS and list their names or details",
	Long: `Search for one or more keys stored in a Key Management System (KMS).

OUTPUT FORMATS:
  By default, this command prints a simple list of key names (URIs), one per line.
  Use the --json flag to output detailed information in JSON format, including
  each key's name and corresponding public key in PEM format.

SUPPORTED KMS TYPES:
  - mackms:   macOS Keychain and Secure Enclave (Secure Enclave requires signed binaries)
  - tpmkms:   Trusted Platform Module (TPM) 2.0

URI SYNTAX:
  The <kms-uri> format is: <kms-type>:[query-params]

  Query parameters are optional and allow you to filter search results.
  Multiple parameters can be combined using standard URI query syntax.

QUERY PARAMETERS:

  TPM (tpmkms:)
    - ak=true     Search only attestation keys (AKs)
    - ak=false    Search only application keys (non-AKs)
    - name=<name> Search for a key with the specified name
    - (no param)  Search all keys (both AKs and application keys)

  macOS Keychain and Secure Enclave (mackms:)
    - label=<name>  Search keys with the specified label/name
    - hash=<hex>    Search keys with the given hash (hexadecimal format)
    - tag=<tag>     Search keys with the given tag (default: com.smallstep.crypto)
    - se=true       Search only keys on the Secure Enclave (requires signed binary)
    - (no param)    Search all keys on both Keychain and Secure Enclave`,
	Example: `  # Search all keys on macOS Keychain/Secure Enclave:
  step-kms-plugin search mackms:

  # Search all keys with a custom tag:
  step-kms-plugin search mackms:tag=com.example.crypto

  # Search all keys (application and attestation keys) on a TPM:
  step-kms-plugin search tpmkms:

  # Search all keys on a TPM with a custom storage directory:
  step-kms-plugin search tpmkms:storage-directory=/tmp/tpmobjects

  # Search only attestation keys (AKs) on a TPM:
  step-kms-plugin search tpmkms:ak=true

  # Search only application keys (non-AKs) on a TPM:
  step-kms-plugin search tpmkms:ak=false

  # Search TPM keys and output details in JSON format with public keys:
  step-kms-plugin search --json tpmkms:ak=false`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return showErrUsage(cmd)
		}

		flags := cmd.Flags()

		kuri, name, err := getURIAndNameForFS(flagutil.MustString(flags, "kms"), args[0])
		if err != nil {
			return err
		}

		km, err := openKMS(cmd.Context(), kuri)
		if err != nil {
			return fmt.Errorf("failed to load key manager: %w", err)
		}
		defer km.Close()

		searchKMS, ok := km.(interface {
			SearchKeys(*apiv1.SearchKeysRequest) (*apiv1.SearchKeysResponse, error)
		})
		if !ok {
			return fmt.Errorf("the KMS does not implement the SearchKeys method")
		}

		results, err := searchKMS.SearchKeys(&apiv1.SearchKeysRequest{
			Query: name,
		})
		if err != nil {
			return err
		}

		if flagutil.MustBool(flags, "json") {
			keys := []map[string]any{}
			for _, r := range results.Results {
				block, err := pemutil.Serialize(r.PublicKey)
				if err != nil {
					return fmt.Errorf("failed to serialize the public key: %w", err)
				}

				keys = append(keys, map[string]any{
					"name":      r.Name,
					"publicKey": string(pem.EncodeToMemory(block)),
				})
			}

			b, err := json.MarshalIndent(map[string]any{
				"keys": keys,
			}, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal: %w", err)
			}
			fmt.Println(string(b))
		} else {
			for _, r := range results.Results {
				fmt.Println(r.Name)
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(searchCmd)
	searchCmd.SilenceUsage = true

	flags := searchCmd.Flags()
	flags.SortFlags = false
	flags.Bool("json", false, "Show the output using JSON")
}
