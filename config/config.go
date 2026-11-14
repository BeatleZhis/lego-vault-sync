package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Значения по умолчанию, которые подставляются, если поле не задано в конфиге.
const (
	DefaultRequestTimeoutSec       = 60
	DefaultCheckCertIntervalMin    = 600
	DefaultCertRefreshIntervalDays = 14
	DefaultLogLevel                = "debug"
	DefaultLegoDirectory           = "staging"
	LegoDirectoryProduction        = "production"
	DefaultAccountSecretPath       = "acme-account"
)

// Config описывает конфигурацию сервиса (config.yaml).
type Config struct {
	DNSProvider string      `yaml:"DNSProvider"`
	Vault       VaultConfig `yaml:"vault"`
	Certs       struct {
		Email   string   `yaml:"email"`
		Domains []string `yaml:"domains,flow"`
	} `yaml:"certs"`
	LegoDirectory           string `yaml:"legoDirectory"`
	CheckCertIntervalMin    int    `yaml:"checkCertIntervalMin"`
	CertRefreshIntervalDays int    `yaml:"certRefreshIntervalDays"`
	LogLevel                string `yaml:"logLevel"`
}

// VaultConfig описывает подключение к HashiCorp Vault.
type VaultConfig struct {
	Address   string `yaml:"address"`
	AuthType  string `yaml:"authType"`
	Token     string `yaml:"token"`
	RoleID    string `yaml:"roleID"`
	SecretID  string `yaml:"secretID"`
	MountPath string `yaml:"mountPath"`
	CertPath  string `yaml:"certPath"`
	// AccountPath — путь секрета в KV v2, где хранятся ключ и регистрация
	// ACME-аккаунта. Диск пода не используется: состояние живёт в Vault.
	AccountPath string `yaml:"accountPath"`
	// RequestTimeout — таймаут одного запроса к Vault в секундах.
	// Ключ в YAML: requestTimeout.
	RequestTimeout int `yaml:"requestTimeout"`
}

// Load читает конфигурацию из файла, подставляет значения по умолчанию
// и проверяет её корректность.
func Load(path string) (Config, error) {
	var cfg Config

	file, err := os.Open(path)
	if err != nil {
		return cfg, fmt.Errorf("не удалось открыть файл конфигурации %q: %w", path, err)
	}
	defer file.Close()

	if err := yaml.NewDecoder(file).Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("не удалось разобрать YAML-конфигурацию %q: %w", path, err)
	}

	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return cfg, err
	}

	return cfg, nil
}

// applyDefaults нормализует значения и подставляет дефолты.
func (c *Config) applyDefaults() {
	c.DNSProvider = strings.TrimSpace(c.DNSProvider)
	c.Certs.Email = strings.TrimSpace(c.Certs.Email)
	c.LegoDirectory = strings.ToLower(strings.TrimSpace(c.LegoDirectory))
	c.LogLevel = strings.ToLower(strings.TrimSpace(c.LogLevel))
	c.Vault.AuthType = strings.ToLower(strings.TrimSpace(c.Vault.AuthType))
	c.Vault.Address = strings.TrimSpace(c.Vault.Address)
	c.Vault.MountPath = strings.Trim(c.Vault.MountPath, "/ ")
	c.Vault.CertPath = strings.Trim(c.Vault.CertPath, "/ ")
	c.Vault.AccountPath = strings.Trim(c.Vault.AccountPath, "/ ")

	for i := range c.Certs.Domains {
		c.Certs.Domains[i] = strings.TrimSpace(c.Certs.Domains[i])
	}

	if c.LegoDirectory == "" {
		c.LegoDirectory = DefaultLegoDirectory
	}
	if c.Vault.AccountPath == "" {
		c.Vault.AccountPath = DefaultAccountSecretPath
	}
	if c.LogLevel == "" {
		c.LogLevel = DefaultLogLevel
	}
	if c.Vault.RequestTimeout <= 0 {
		c.Vault.RequestTimeout = DefaultRequestTimeoutSec
	}
	if c.CheckCertIntervalMin <= 0 {
		c.CheckCertIntervalMin = DefaultCheckCertIntervalMin
	}
	if c.CertRefreshIntervalDays <= 0 {
		c.CertRefreshIntervalDays = DefaultCertRefreshIntervalDays
	}
}

// validate проверяет обязательные параметры, чтобы сервис падал при старте,
// а не в середине цикла обновления.
func (c Config) validate() error {
	if c.DNSProvider == "" {
		return errors.New("не задан DNSProvider")
	}
	if c.Certs.Email == "" {
		return errors.New("не задан certs.email")
	}
	if len(c.Certs.Domains) == 0 {
		return errors.New("не задан список доменов certs.domains")
	}

	seen := make(map[string]struct{}, len(c.Certs.Domains))
	for _, domain := range c.Certs.Domains {
		if domain == "" {
			return errors.New("certs.domains содержит пустое значение")
		}
		if _, ok := seen[domain]; ok {
			return fmt.Errorf("домен %q указан в certs.domains несколько раз", domain)
		}
		seen[domain] = struct{}{}
	}

	if c.LegoDirectory != DefaultLegoDirectory && c.LegoDirectory != LegoDirectoryProduction {
		return fmt.Errorf("неизвестный legoDirectory %q: ожидается %q или %q",
			c.LegoDirectory, DefaultLegoDirectory, LegoDirectoryProduction)
	}

	if c.Vault.Address == "" {
		return errors.New("не задан vault.address")
	}
	if c.Vault.MountPath == "" {
		return errors.New("не задан vault.mountPath")
	}
	if c.Vault.RequestTimeout <= 0 {
		return errors.New("vault.requestTimeout должен быть больше нуля")
	}

	switch c.Vault.AuthType {
	case "token":
		if c.Vault.Token == "" {
			return errors.New(`для vault.authType = "token" требуется vault.token`)
		}
	case "approle":
		if c.Vault.RoleID == "" || c.Vault.SecretID == "" {
			return errors.New(`для vault.authType = "approle" требуются vault.roleID и vault.secretID`)
		}
	default:
		return fmt.Errorf("неизвестный vault.authType %q: ожидается %q или %q",
			c.Vault.AuthType, "token", "approle")
	}

	if c.CheckCertIntervalMin <= 0 {
		return errors.New("checkCertIntervalMin должен быть больше нуля")
	}
	if c.CertRefreshIntervalDays <= 0 {
		return errors.New("certRefreshIntervalDays должен быть больше нуля")
	}
	if c.Vault.AccountPath == "" {
		return errors.New("не задан vault.accountPath (путь секрета ACME-аккаунта)")
	}

	return nil
}

// IsStaging сообщает, работаем ли мы с тестовым окружением Let's Encrypt.
func (c Config) IsStaging() bool {
	return c.LegoDirectory != LegoDirectoryProduction
}

// SecretPath возвращает путь секрета сертификата внутри KV v2:
// <certPath>/<domain>.
func (c VaultConfig) SecretPath(domain string) string {
	return joinPath(c.CertPath, domain)
}

// AccountSecretPath возвращает путь секрета с ключом и регистрацией
// ACME-аккаунта: <accountPath>/<окружение>. Для staging и production
// используются разные секреты, чтобы окружения не пересекались.
func (c VaultConfig) AccountSecretPath(environment string) string {
	return joinPath(c.AccountPath, environment)
}

// joinPath склеивает два сегмента пути, нормализуя слэши по краям, поэтому
// "/", "certs/" и "" дают предсказуемый результат без двойных слэшей в URL.
func joinPath(base, name string) string {
	base = strings.Trim(base, "/ ")
	name = strings.Trim(name, "/ ")

	switch {
	case base == "":
		return name
	case name == "":
		return base
	default:
		return base + "/" + name
	}
}
