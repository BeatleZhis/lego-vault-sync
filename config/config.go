package config

type Config struct {
	DNSProvider string      `yaml:"DNSProvider"`
	Vault       VaultConfig `yaml:"vault"`
	Certs       struct {
		Email   string   `yaml:"email"`
		Domains []string `yaml:"domains,flow"`
	} `yaml:"certs"`
	LegoDirectory string `yaml:"legoDirectory"`
}

type VaultConfig struct {
	Address           string `yaml:"address"`
	AuthType          string `yaml:"authType"`
	Token             string `yaml:"token"`
	RoleID            string `yaml:"roleID"`
	SecretID          string `yaml:"secretID"`
	MountPath         string `yaml:"mountPath"`
	RequestTimeoutSec int    `yaml:"requestTimeoutSec"`
}
