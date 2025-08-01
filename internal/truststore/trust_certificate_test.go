package truststore_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	lxdShared "github.com/canonical/lxd/shared"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/terraform-lxd/terraform-provider-lxd/internal/acctest"
	"github.com/terraform-lxd/terraform-provider-lxd/internal/truststore"
)

func TestAccTrustCertificate_content(t *testing.T) {
	certName := acctest.GenerateName(2, "-")
	cert, fingerprint := generateCert(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccTrustCertificate_content(certName, cert),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("lxd_trust_certificate.cert", "name", certName),
					resource.TestCheckResourceAttr("lxd_trust_certificate.cert", "type", "client"),
					resource.TestCheckResourceAttr("lxd_trust_certificate.cert", "content", cert),
					resource.TestCheckResourceAttr("lxd_trust_certificate.cert", "fingerprint", fingerprint),
					// Ensure path is not set.
					resource.TestCheckNoResourceAttr("lxd_trust_certificate.cert", "path"),
				),
			},
		},
	})
}

func TestAccTrustCertificate_path(t *testing.T) {
	certName := acctest.GenerateName(2, "-")
	certPath := filepath.Join(t.TempDir(), "client.crt")
	cert, fingerprint := generateCert(t)

	// Write certificate to a temporary location.
	err := os.WriteFile(certPath, []byte(cert), os.ModePerm)
	if err != nil {
		t.Fatalf("Failed to write temporary certificate file: %v", err)
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccTrustCertificate_path(certName, certPath),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("lxd_trust_certificate.cert", "name", certName),
					resource.TestCheckResourceAttr("lxd_trust_certificate.cert", "path", certPath),
					resource.TestCheckResourceAttr("lxd_trust_certificate.cert", "type", "client"),
					resource.TestCheckResourceAttr("lxd_trust_certificate.cert", "fingerprint", fingerprint),
					// Ensure content is not set.
					resource.TestCheckNoResourceAttr("lxd_trust_certificate.cert", "content"),
				),
			},
		},
	})
}

func TestAccTrustCertificate_type(t *testing.T) {
	certName := acctest.GenerateName(2, "-")
	cert, fingerprint := generateCert(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccTrustCertificate_type(certName, "client", cert),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("lxd_trust_certificate.cert", "name", certName),
					resource.TestCheckResourceAttr("lxd_trust_certificate.cert", "type", "client"),
					resource.TestCheckResourceAttr("lxd_trust_certificate.cert", "content", cert),
					resource.TestCheckResourceAttr("lxd_trust_certificate.cert", "fingerprint", fingerprint),
					resource.TestCheckResourceAttr("lxd_trust_certificate.cert", "projects.#", "0"),
				),
			},
			{
				Config: testAccTrustCertificate_type(certName, "metrics", cert),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("lxd_trust_certificate.cert", "name", certName),
					resource.TestCheckResourceAttr("lxd_trust_certificate.cert", "type", "metrics"),
					resource.TestCheckResourceAttr("lxd_trust_certificate.cert", "content", cert),
					resource.TestCheckResourceAttr("lxd_trust_certificate.cert", "fingerprint", fingerprint),
				),
			},
		},
	})
}

func TestAccTrustCertificate_rename(t *testing.T) {
	certName1 := acctest.GenerateName(2, "-")
	certName2 := acctest.GenerateName(2, "-")
	cert, fingerprint := generateCert(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccTrustCertificate_content(certName1, cert),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("lxd_trust_certificate.cert", "name", certName1),
					resource.TestCheckResourceAttr("lxd_trust_certificate.cert", "content", cert),
					resource.TestCheckResourceAttr("lxd_trust_certificate.cert", "fingerprint", fingerprint),
				),
			},
			{
				Config: testAccTrustCertificate_content(certName2, cert),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("lxd_trust_certificate.cert", "name", certName2),
					resource.TestCheckResourceAttr("lxd_trust_certificate.cert", "content", cert),
					resource.TestCheckResourceAttr("lxd_trust_certificate.cert", "fingerprint", fingerprint),
				),
			},
		},
	})
}

func TestAccTrustCertificate_restricted(t *testing.T) {
	certName := acctest.GenerateName(2, "-")
	cert, fingerprint := generateCert(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccTrustCertificate_content(certName, cert),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("lxd_trust_certificate.cert", "name", certName),
					resource.TestCheckResourceAttr("lxd_trust_certificate.cert", "content", cert),
					resource.TestCheckResourceAttr("lxd_trust_certificate.cert", "fingerprint", fingerprint),
					resource.TestCheckResourceAttr("lxd_trust_certificate.cert", "projects.#", "0"),
				),
			},
			{
				Config: testAccTrustCertificate_content(certName, cert, "default"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("lxd_trust_certificate.cert", "name", certName),
					resource.TestCheckResourceAttr("lxd_trust_certificate.cert", "content", cert),
					resource.TestCheckResourceAttr("lxd_trust_certificate.cert", "fingerprint", fingerprint),
					resource.TestCheckResourceAttr("lxd_trust_certificate.cert", "projects.#", "1"),
					resource.TestCheckResourceAttr("lxd_trust_certificate.cert", "projects.0", "default"),
				),
			},
		},
	})
}
func TestAccTrustCertificate_generatedCertificate(t *testing.T) {
	certName := acctest.GenerateName(2, "-")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders: map[string]resource.ExternalProvider{
			"tls": {
				VersionConstraint: "4.0.5",
				Source:            "hashicorp/tls",
			},
		},
		Steps: []resource.TestStep{
			{
				// Ensure the certificate generated within the same Terraform
				// configuration as the trust_certificate can be used.
				Config: testAccTrustCertificate_generatedCertificate(certName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("lxd_trust_certificate.cert", "name", certName),
					resource.TestCheckResourceAttrSet("lxd_trust_certificate.cert", "content"),
					resource.TestCheckResourceAttrSet("lxd_trust_certificate.cert", "fingerprint"),
				),
			},
		},
	})
}

func testAccTrustCertificate_content(name string, cert string, projects ...string) string {
	return fmt.Sprintf(`
resource "lxd_trust_certificate" "cert" {
  name    = "%s"
  content = <<-EOF
%s
EOF
  projects = [%s]
}
	`, name, strings.TrimRight(cert, "\n"), acctest.QuoteStrings(projects))
}

func testAccTrustCertificate_path(name string, certPath string, projects ...string) string {
	return fmt.Sprintf(`
resource "lxd_trust_certificate" "cert" {
  name     = "%s"
  path     = "%s"
  projects = [%s]
}
	`, name, certPath, acctest.QuoteStrings(projects))
}

func testAccTrustCertificate_type(name string, certType string, cert string, projects ...string) string {
	return fmt.Sprintf(`
resource "lxd_trust_certificate" "cert" {
  name     = "%s"
  type     = "%s"
  content = <<-EOF
%s
EOF
  projects = [%s]
}
	`, name, certType, strings.TrimRight(cert, "\n"), acctest.QuoteStrings(projects))
}

func testAccTrustCertificate_generatedCertificate(certName string) string {
	return fmt.Sprintf(`
resource "tls_private_key" "client_key" {
  algorithm = "ECDSA"
}

resource "tls_self_signed_cert" "client_cert" {
  private_key_pem       = tls_private_key.client_key.private_key_pem
  validity_period_hours = 1

  allowed_uses = [
    "client_auth",
  ]
}

resource "lxd_trust_certificate" "cert" {
  name    = %q
  content = tls_self_signed_cert.client_cert.cert_pem
}
`, certName)
}

func generateCert(t *testing.T) (certificate string, fingerprint string) {
	certBytes, _, err := lxdShared.GenerateMemCert(true, lxdShared.CertOptions{AddHosts: false})
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	certX509, err := truststore.ParseCertX509(certBytes)
	if err != nil {
		t.Fatalf("Failed to parse generated certificate: %v", err)
	}

	return string(certBytes), lxdShared.CertFingerprint(certX509)
}
