package cmd

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/codeswhat/sockguard/v3/app/internal/tlsbootstrap"
)

var tlsCmd = &cobra.Command{
	Use:   "tls",
	Short: "TLS provisioning helpers",
}

var (
	tlsBootstrapDir         string
	tlsBootstrapServerNames []string
	tlsBootstrapClients     []string
	tlsBootstrapForce       bool
)

var tlsBootstrapCmd = &cobra.Command{
	Use:   "bootstrap",
	Short: "Create a CA, server certificate and client certificates for mutual TLS",
	Long: `Create the certificate material for listen.tls mutual TLS in one directory:
an ECDSA P-256 CA, a server certificate for the given names, and one client
certificate per --client. Each client certificate carries the client name as
its CommonName and its only DNS SAN, which is what
clients.client_certificate_profiles matches with common_names or dns_names.

The directory is created 0700 and every file 0600. An existing directory
that group or others can access is refused. Rerunning reuses the CA and any
valid certificate, and adds new clients. A stale or mismatched certificate is
an error unless --force, which reissues the server certificate and the listed
clients with new keys. The CA is never replaced; move ca.pem and ca-key.pem
aside to rotate it. Files are written all-or-nothing.

The config snippet to enable mTLS is printed on stdout.`,
	Args: cobra.NoArgs,
	RunE: runTLSBootstrap,
}

func init() {
	tlsBootstrapCmd.Flags().StringVar(&tlsBootstrapDir, "dir", "", "directory for the generated files (created 0700)")
	tlsBootstrapCmd.Flags().StringSliceVar(&tlsBootstrapServerNames, "server-name", nil, "DNS name or IP address the server certificate must cover (repeatable)")
	tlsBootstrapCmd.Flags().StringSliceVar(&tlsBootstrapClients, "client", nil, "client name; becomes the certificate CommonName and profile/owner name (repeatable)")
	tlsBootstrapCmd.Flags().BoolVar(&tlsBootstrapForce, "force", false, "reissue the server certificate and listed client certificates even when existing ones are valid")
	_ = tlsBootstrapCmd.MarkFlagRequired("dir")
	tlsCmd.AddCommand(tlsBootstrapCmd)
	rootCmd.AddCommand(tlsCmd)
}

func runTLSBootstrap(cmd *cobra.Command, args []string) error {
	res, err := tlsbootstrap.Bootstrap(tlsbootstrap.Options{
		Dir:         tlsBootstrapDir,
		ServerNames: tlsBootstrapServerNames,
		Clients:     tlsBootstrapClients,
		Force:       tlsBootstrapForce,
	})
	if err != nil {
		return fmt.Errorf("tls bootstrap: %w", err)
	}
	errOut := cmd.ErrOrStderr()
	if res.CreatedCA {
		fmt.Fprintf(errOut, "created CA        %s\n", res.CAFile)
	} else {
		fmt.Fprintf(errOut, "reused CA         %s\n", res.CAFile)
	}
	fmt.Fprintf(errOut, "%-9s server  %s\n", res.Server, res.ServerCert)
	for _, name := range res.ClientNames {
		fmt.Fprintf(errOut, "%-9s client  %s  (%s)\n", res.Clients[name], name, res.ClientFiles[name][0])
	}
	writeTLSBootstrapSnippet(cmd.OutOrStdout(), res)
	return nil
}

func writeTLSBootstrapSnippet(w io.Writer, res *tlsbootstrap.Result) {
	var b strings.Builder
	b.WriteString("listen:\n  tls:\n")
	fmt.Fprintf(&b, "    cert_file: %s\n    key_file: %s\n    client_ca_file: %s\n", res.ServerCert, res.ServerKey, res.CAFile)
	b.WriteString("clients:\n  client_certificate_profiles:\n")
	for _, name := range res.ClientNames {
		// Quoted so YAML cannot read 007, 1e3, true or null as another scalar.
		// Client names are limited to [a-z0-9.-], so %q is a valid YAML
		// double-quoted scalar with no escapes.
		fmt.Fprintf(&b, "    - profile: %q\n      common_names: [%q]\n", name, name)
	}
	b.WriteString("  profiles:\n")
	for _, name := range res.ClientNames {
		fmt.Fprintf(&b, "    - name: %q\n      ownership:\n        owner: %q\n      # add rules for this profile\n", name, name)
	}
	fmt.Fprint(w, b.String())
}
