//go:build darwin && cgo

package cmd

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/smallstep/step-kms-plugin/internal/flagutil"

	cf "github.com/smallstep/step-kms-plugin/internal/darwin/corefoundation"
	"github.com/smallstep/step-kms-plugin/internal/darwin/security"
)

// ctkEntry holds the extracted data for one CTK identity.
type ctkEntry struct {
	Subject   string    `json:"subject"`
	Serial    string    `json:"serial"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	Token     string    `json:"token"`
	KeyType   string    `json:"key_type"`
	KeySize   int       `json:"key_size"`
}

var ctkCmd = &cobra.Command{
	Use:   "ctk [serial]",
	Short: "List identities stored in CryptoTokenKit tokens",
	Long: `List identities (certificate + private key pairs) stored in CryptoTokenKit
tokens on macOS. By default, all CTK tokens are searched and the results are
displayed in a table. Pass an optional serial number to filter to a single
identity. Use --token to narrow the search to a specific token, --json to get
machine-readable output, or --pem to export the certificate in PEM format.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		flags := cmd.Flags()
		tokenFlag := flagutil.MustString(flags, "token")
		jsonFlag := flagutil.MustBool(flags, "json")
		pemFlag := flagutil.MustBool(flags, "pem")

		var serialFilter string
		if len(args) == 1 {
			serialFilter = args[0]
		} else if len(args) > 1 {
			return showErrUsage(cmd)
		}

		// Build the base query dictionary.
		query := cf.Dictionary{
			security.KSecClass:           security.KSecClassIdentity,
			security.KSecAttrAccessGroup: security.KSecAttrAccessGroupToken,
			security.KSecReturnRef:       cf.True,
			security.KSecMatchLimit:      security.KSecMatchLimitAll,
		}

		// Optionally narrow to a specific token.
		var tokenID *cf.StringRef
		if tokenFlag != "" {
			var err error
			tokenID, err = cf.NewString(tokenFlag)
			if err != nil {
				return err
			}
			defer tokenID.Release()
			query[security.KSecAttrTokenID] = tokenID
		}

		cfQuery, err := cf.NewDictionary(query)
		if err != nil {
			return err
		}
		defer cfQuery.Release()

		var result cf.TypeRef
		if err := security.SecItemCopyMatching(cfQuery, &result); err != nil {
			return err
		}

		array := cf.NewArrayRef(result)
		defer array.Release()

		// Collect entries, processing each identity in its own scope so that
		// deferred releases fire at the end of each iteration.
		entries := make([]ctkEntry, 0, array.Len())
		certs := make([]*x509.Certificate, 0, array.Len())

		for i := 0; i < array.Len(); i++ {
			entry, cert, err := func() (ctkEntry, *x509.Certificate, error) {
				identity := security.NewSecIdentityRef(array.Get(i))
				identity.Retain()
				defer identity.Release()

				certRef, err := identity.SecCertificateRef()
				if err != nil {
					return ctkEntry{}, nil, err
				}
				defer certRef.Release()

				certificate, err := certRef.Certificate()
				if err != nil {
					return ctkEntry{}, nil, err
				}

				keyRef, err := identity.SecKeyRef()
				if err != nil {
					return ctkEntry{}, nil, err
				}
				defer keyRef.Release()

				attrs := security.SecKeyCopyAttributes(keyRef)
				defer attrs.Release()

				token := security.GetSecAttrTokenID(attrs)

				serialHex := hex.EncodeToString(certificate.SerialNumber.Bytes())

				var keyType string
				var keySize int
				switch pub := certificate.PublicKey.(type) {
				case *ecdsa.PublicKey:
					keyType = fmt.Sprintf("EC P-%d", pub.Curve.Params().BitSize)
					keySize = pub.Curve.Params().BitSize
				case *rsa.PublicKey:
					keyType = fmt.Sprintf("RSA %d", pub.N.BitLen())
					keySize = pub.N.BitLen()
				default:
					keyType = "unknown"
					keySize = 0
				}

				e := ctkEntry{
					Subject:   certificate.Subject.CommonName,
					Serial:    serialHex,
					NotBefore: certificate.NotBefore,
					NotAfter:  certificate.NotAfter,
					Token:     token,
					KeyType:   keyType,
					KeySize:   keySize,
				}

				return e, certificate, nil
			}()
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: skipping item %d: %v\n", i, err)
				continue
			}
			entries = append(entries, entry)
			certs = append(certs, cert)
		}

		// Filter by serial if a positional arg was given.
		if serialFilter != "" {
			filtered := entries[:0]
			filteredCerts := certs[:0]
			for i, e := range entries {
				if strings.EqualFold(e.Serial, serialFilter) {
					filtered = append(filtered, e)
					filteredCerts = append(filteredCerts, certs[i])
				}
			}
			if len(filtered) == 0 {
				return fmt.Errorf("no identity found with serial %q", serialFilter)
			}
			entries = filtered
			certs = filteredCerts
		}

		// --pem: output the certificate in PEM format.
		if pemFlag {
			if serialFilter == "" {
				return fmt.Errorf("--pem requires a serial number argument")
			}
			return outputCert(certs[0])
		}

		// --json: output a JSON array.
		if jsonFlag {
			type jsonEntry struct {
				Subject   string `json:"subject"`
				Serial    string `json:"serial"`
				NotBefore string `json:"not_before"`
				NotAfter  string `json:"not_after"`
				Token     string `json:"token"`
				KeyType   string `json:"key_type"`
				KeySize   int    `json:"key_size"`
			}
			out := make([]jsonEntry, len(entries))
			for i, e := range entries {
				out[i] = jsonEntry{
					Subject:   e.Subject,
					Serial:    e.Serial,
					NotBefore: e.NotBefore.UTC().Format(time.RFC3339),
					NotAfter:  e.NotAfter.UTC().Format(time.RFC3339),
					Token:     e.Token,
					KeyType:   e.KeyType,
					KeySize:   e.KeySize,
				}
			}
			data, err := json.MarshalIndent(out, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(data))
			return nil
		}

		// Default: table output.
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "SUBJECT\tSERIAL\tNOT BEFORE\tNOT AFTER\tTOKEN\tKEY")
		for _, e := range entries {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
				e.Subject,
				e.Serial,
				e.NotBefore.Format("2006-01-02"),
				e.NotAfter.Format("2006-01-02"),
				e.Token,
				e.KeyType,
			)
		}
		return w.Flush()
	},
}

func init() {
	rootCmd.AddCommand(ctkCmd)
	ctkCmd.SilenceUsage = true

	flags := ctkCmd.Flags()
	flags.SortFlags = false
	flags.String("token", "", "Limit search to the CTK token with this identifier")
	flags.Bool("json", false, "Output results as a JSON array")
	flags.Bool("pem", false, "Output the certificate in PEM format (requires a serial number argument)")
}
