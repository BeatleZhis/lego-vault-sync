package config

import (
	"os"
	"path/filepath"
	"testing"
)

const minimalConfig = `
DNSProvider: regru
vault:
  address: "https://vault.example.com:8200/"
  authType: approle
  roleID: role
  secretID: secret
  mountPath: tls
certs:
  email: admin@example.org
  domains: ["example.com", "*.example.com"]
`

func writeConfig(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("не удалось записать тестовый конфиг: %v", err)
	}

	return path
}

func TestLoadAppliesDefaults(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalConfig))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Vault.AccountPath != DefaultAccountSecretPath {
		t.Fatalf("vault.accountPath = %q, ожидался %q", cfg.Vault.AccountPath, DefaultAccountSecretPath)
	}
	if want := "acme-account/staging"; cfg.Vault.AccountSecretPath(cfg.LegoDirectory) != want {
		t.Fatalf("AccountSecretPath() = %q, ожидался %q", cfg.Vault.AccountSecretPath(cfg.LegoDirectory), want)
	}
	if cfg.Vault.RequestTimeout != DefaultRequestTimeoutSec {
		t.Fatalf("requestTimeout = %d, ожидался %d", cfg.Vault.RequestTimeout, DefaultRequestTimeoutSec)
	}
	if cfg.CheckCertIntervalMin != DefaultCheckCertIntervalMin {
		t.Fatalf("checkCertIntervalMin = %d, ожидался %d", cfg.CheckCertIntervalMin, DefaultCheckCertIntervalMin)
	}
	if cfg.CertRefreshIntervalDays != DefaultCertRefreshIntervalDays {
		t.Fatalf("certRefreshIntervalDays = %d, ожидался %d", cfg.CertRefreshIntervalDays, DefaultCertRefreshIntervalDays)
	}
	if !cfg.IsStaging() {
		t.Fatal("без legoDirectory окружение должно быть staging")
	}
}

func TestAccountPathFollowsCertPath(t *testing.T) {
	withCertPath := `
DNSProvider: regru
vault:
  address: "https://vault.example.com:8200/"
  authType: approle
  roleID: role
  secretID: secret
  mountPath: devops
  certPath: tls/
certs:
  email: admin@example.org
  domains: ["example.com"]
legoDirectory: production
`
	cfg, err := Load(writeConfig(t, withCertPath))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if want := "tls/acme-account"; cfg.Vault.AccountPath != want {
		t.Fatalf("vault.accountPath = %q, ожидался %q", cfg.Vault.AccountPath, want)
	}
	if want := "tls/acme-account/production"; cfg.Vault.AccountSecretPath(cfg.LegoDirectory) != want {
		t.Fatalf("AccountSecretPath() = %q, ожидался %q", cfg.Vault.AccountSecretPath(cfg.LegoDirectory), want)
	}
}

func TestAccountSecretPathSeparatesEnvironments(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalConfig+"\nlegoDirectory: production\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if want := "acme-account/production"; cfg.Vault.AccountSecretPath(cfg.LegoDirectory) != want {
		t.Fatalf("AccountSecretPath() = %q, ожидался %q", cfg.Vault.AccountSecretPath(cfg.LegoDirectory), want)
	}
	if cfg.IsStaging() {
		t.Fatal("legoDirectory: production должен отключать staging")
	}
}

func TestLoadRejectsMissingSecretID(t *testing.T) {
	broken := `
DNSProvider: regru
vault:
  address: "https://vault.example.com:8200/"
  authType: approle
  roleID: role
  mountPath: tls
certs:
  email: admin@example.org
  domains: ["example.com"]
`

	if _, err := Load(writeConfig(t, broken)); err == nil {
		t.Fatal("конфиг без secretID должен быть отвергнут")
	}
}

func TestAccountSecretPathNormalization(t *testing.T) {
	cases := map[string]string{
		"":          "staging",
		"/":         "staging",
		"acme":      "acme/staging",
		"acme/":     "acme/staging",
		"/acme/":    "acme/staging",
		"/acme/v2/": "acme/v2/staging",
	}

	for accountPath, want := range cases {
		got := VaultConfig{AccountPath: accountPath}.AccountSecretPath("staging")
		if got != want {
			t.Errorf("accountPath %q: AccountSecretPath() = %q, ожидался %q", accountPath, got, want)
		}
	}
}

func TestSecretPathNormalization(t *testing.T) {
	cases := map[string]string{
		"":        "example.com",
		"/":       "example.com",
		"certs":   "certs/example.com",
		"certs/":  "certs/example.com",
		"/certs/": "certs/example.com",
	}

	for certPath, want := range cases {
		got := VaultConfig{CertPath: certPath}.SecretPath("example.com")
		if got != want {
			t.Errorf("certPath %q: SecretPath() = %q, ожидался %q", certPath, got, want)
		}
	}
}
