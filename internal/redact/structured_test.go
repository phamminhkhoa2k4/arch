package redact

import (
	"strings"
	"testing"
)

// Structured credential formats are masked wherever they appear in a
// value: cloud keys, JWTs, connection-string passwords, private key
// blocks and tokens carried in URLs or headers.
func TestScrubStringStructuredSecrets(t *testing.T) {
	googleKey := "AIza" + strings.Repeat("aB9", 11) + "Zz" // AIza + 35
	cases := map[string]string{
		// JWT: every segment must disappear, the surrounding text stays.
		"curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c' https://x": "curl -H 'Authorization: Bearer " + Mask + "' https://x",
		// AWS access key id and secret assigned by name.
		"aws s3 ls s3://bucket --region eu-west-1 AKIAIOSFODNN7EXAMPLE":  "aws s3 ls s3://bucket --region eu-west-1 " + Mask,
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY": "AWS_SECRET_ACCESS_KEY=" + Mask,
		// Google API key.
		"GET /maps?key=" + googleKey + "&lang=en": "GET /maps?key=" + Mask + "&lang=en",
		// Azure Storage connection string: AccountKey masked, name kept.
		"DefaultEndpointsProtocol=https;AccountName=acme;AccountKey=Base64Key%2B%3D;EndpointSuffix=core.windows.net": "DefaultEndpointsProtocol=https;AccountName=acme;AccountKey=" + Mask + ";EndpointSuffix=core.windows.net",
		// Connection-string password: username kept, password masked.
		"postgres://appuser:s3cr3t@db.internal:5432/prod": "postgres://appuser:" + Mask + "@db.internal:5432/prod",
		// A password may itself contain "@" — nothing may survive.
		"mysql://root:p@ss@10.0.0.1:3306/db": "mysql://root:" + Mask + "@10.0.0.1:3306/db",
		// Long token in a URL query string; sibling params survive.
		"https://api.internal/v1/data?access_token=abcdef123456&page=2": "https://api.internal/v1/data?access_token=" + Mask + "&page=2",
		// Credential headers and -H fragments.
		"curl -H 'X-Api-Key: sk-1234567890abcdef' https://x": "curl -H 'X-Api-Key: " + Mask + "' https://x",
		// Private key block: replaced atomically, body never survives.
		"key material -----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0\n-----END RSA PRIVATE KEY-----\nrest": "key material " + Mask + "\nrest",
		// A truncated block (BEGIN without END) masks to the end.
		"hdr -----BEGIN OPENSSH PRIVATE KEY-----\nAAAAsecret": "hdr " + Mask,
		// JDBC-style connection string keeps its parameter structure.
		"jdbc:postgresql://appuser:s3cr3t@db.internal:5432/prod?ssl=true": "jdbc:postgresql://appuser:" + Mask + "@db.internal:5432/prod?ssl=true",
	}
	for in, want := range cases {
		got := ScrubString(in)
		if got != want {
			t.Errorf("ScrubString(%q) = %q, want %q", in, got, want)
		}
	}
}

// Correlation data must survive the new shape rules: hosts, ports,
// passwords-free URLs, emails outside a URL and plain commands.
func TestScrubStringKeepsCorrelationData(t *testing.T) {
	keeps := []string{
		"https://internal.local:8443/health",
		"postgres://appuser@db.internal/prod",
		"http://user@example.com/path",
		"git clone https://github.com/acme/repo.git",
		"systemctl start nginx",
		"mail to ops@example.com subject done",
		"127.0.0.1:6379",
	}
	for _, in := range keeps {
		if got := ScrubString(in); got != in {
			t.Errorf("ScrubString(%q) = %q, want unchanged", in, got)
		}
	}
}

// The sink choke-point applies the shape rules to every value that is
// not masked by its key name.
func TestRedactMapScrubsShapedValues(t *testing.T) {
	out := RedactMap(map[string]string{
		"command":  "aws configure set aws_secret_access_key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"upstream": "proxy_pass http://appuser:s3cr3t@backend:8080;",
		"state":    "running",
	})
	if strings.Contains(out["command"], "wJalrXUtnFEMI") {
		t.Errorf("aws secret survived: %q", out["command"])
	}
	if strings.Contains(out["upstream"], "s3cr3t") {
		t.Errorf("connection password survived: %q", out["upstream"])
	}
	if out["state"] != "running" {
		t.Errorf("state = %q, want unchanged", out["state"])
	}
}
