package redact

import (
	"strings"
	"testing"
)

// At least twenty common credential-bearing variable names must be
// recognized; none of the correlation-critical names may be.
func TestIsSecretNamePatterns(t *testing.T) {
	secrets := []string{
		"DATABASE_PASSWORD", "DB_PASSWD", "MYSQL_PWD", "REDIS_PASSWORD",
		"MAIL_PASSWORD", "STRIPE_API_KEY", "AWS_SECRET_ACCESS_KEY",
		"AWS_ACCESS_KEY_ID", "GITHUB_TOKEN", "SLACK_BOT_TOKEN",
		"API_TOKEN", "MAPBOX_TOKEN", "TWILIO_AUTH_TOKEN", "PRIVATE_KEY",
		"SSH_PRIVATE_KEY", "OAUTH_CLIENT_SECRET", "SESSION_SECRET",
		"ENCRYPTION_KEY", "SIGNING_KEY", "AUTH_TOKEN", "BEARER_TOKEN",
		"DB_PASSWORD", "APP_CREDENTIALS", "ACCESS_KEY",
	}
	for _, name := range secrets {
		if !IsSecretName(name) {
			t.Errorf("IsSecretName(%q) = false, want true", name)
		}
	}
	if len(secrets) < 20 {
		t.Fatalf("need ≥20 secret patterns, have %d", len(secrets))
	}
	keeps := []string{
		"API_HOST", "PATH", "PWD", "OLDPWD", "HOME", "LANG",
		"DB_HOST", "PORT", "LISTEN_PORT", "DATABASE_URL",
	}
	for _, name := range keeps {
		if IsSecretName(name) {
			t.Errorf("IsSecretName(%q) = true, want false", name)
		}
	}
}

// The entropy bar catches generated tokens but leaves correlation
// data (timestamps, URLs, host:port) intact.
func TestIsHighEntropy(t *testing.T) {
	tokens := []string{
		"sk_live_4eC39HqLyjWDarjtT1zdp7dc",
		"ghp_9fQzK3mWxR8vBnT2uYcLpAeHsDj",
		"aGVsbG8td29ybGQtc2VjcmV0LXRva2VuIQ",
		"0123456789abcdef0123456789ABCDEF",
	}
	for _, v := range tokens {
		if !IsHighEntropy(v) {
			t.Errorf("IsHighEntropy(%q) = false (H=%.2f), want true", v, Shannon(v))
		}
	}
	keeps := []string{
		"2026-10-07T20:51:45Z",
		"https://api.internal.local:8080",
		"127.0.0.1:6379",
		"running",
		"/usr/bin/containerd",
		"sha256:abc123",
		"short",
	}
	for _, v := range keeps {
		if IsHighEntropy(v) {
			t.Errorf("IsHighEntropy(%q) = true (H=%.2f), want false", v, Shannon(v))
		}
	}
}

func TestScrubString(t *testing.T) {
	cases := map[string]string{
		"mysqld --password=hunter2 --skip-grant":             "mysqld --password=" + Mask + " --skip-grant",
		"curl --token abc123 https://x":                      "curl --token " + Mask + " https://x",
		"login password=supersecret&x=1":                     "login password=" + Mask + "&x=1",
		"curl -H 'Authorization: Bearer eyJhbGci' https://x": "curl -H 'Authorization: Bearer " + Mask + "' https://x",
		"redis-cli -pMyStr0ngPass!":                          "redis-cli -p" + Mask,
		"systemctl start nginx":                              "systemctl start nginx",
		"mysql -p -h localhost":                              "mysql -p -h localhost",
	}
	for in, want := range cases {
		if got := ScrubString(in); got != want {
			t.Errorf("ScrubString(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRedactMapKeepsVerdictKeys(t *testing.T) {
	in := map[string]string{
		"state":           "running",
		"active_state":    "active",
		"age_days":        "45",
		"last_request_at": "2026-10-07T20:51:45Z",
		"db_password":     "hunter2",
		"command":         "mysqld --password=hunter2",
	}
	out := RedactMap(in)
	if out["state"] != "running" || out["active_state"] != "active" ||
		out["age_days"] != "45" || out["last_request_at"] != "2026-10-07T20:51:45Z" {
		t.Errorf("verdict keys damaged: %v", out)
	}
	if out["db_password"] != Mask {
		t.Errorf("db_password = %q, want mask", out["db_password"])
	}
	if strings.Contains(out["command"], "hunter2") {
		t.Errorf("inline secret survived: %q", out["command"])
	}
	if RedactMap(nil) != nil {
		t.Error("nil map must stay nil")
	}
}

func TestRedactEnvMasksHighEntropy(t *testing.T) {
	out := RedactEnv(map[string]string{
		"API_HOST":          "https://api.internal.local:8080",
		"RANDOM_BLOB":       "aGVsbG8td29ybGQtc2VjcmV0LXRva2VuIQ",
		"DATABASE_PASSWORD": "supersecret123",
		"PWD":               "/home/user",
	})
	if out["API_HOST"] != "https://api.internal.local:8080" {
		t.Errorf("API_HOST = %q, want kept", out["API_HOST"])
	}
	if out["RANDOM_BLOB"] != Mask {
		t.Errorf("RANDOM_BLOB = %q, want mask", out["RANDOM_BLOB"])
	}
	if out["DATABASE_PASSWORD"] != Mask {
		t.Errorf("DATABASE_PASSWORD = %q, want mask", out["DATABASE_PASSWORD"])
	}
	if out["PWD"] != "/home/user" {
		t.Errorf("PWD = %q, want kept", out["PWD"])
	}
}
