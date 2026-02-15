package main

import (
	"BeatleZhis/lego-vault-sync/config"
	"BeatleZhis/lego-vault-sync/lego"
	"BeatleZhis/lego-vault-sync/vault"
	"os"
	"time"

	"github.com/go-acme/lego/v4/providers/dns"
	log "github.com/sirupsen/logrus"

	"gopkg.in/yaml.v3"
)

func init() {
	log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)
}

func ReadConfig() (config.Config, error) {
	var cfg config.Config
	file, err := os.Open("config.yaml")
	if err != nil {
		return cfg, err
	}
	defer file.Close()
	decoder := yaml.NewDecoder(file)
	err = decoder.Decode(&cfg)
	if err != nil {
		log.Error("Ошибка десериализации YAML:", err)
		return cfg, err
	}
	return cfg, nil
}

func main() {
	config, err := ReadConfig()
	if err != nil {
		log.Fatal(err)
	}
	// DNS provider
	provider, err := dns.NewDNSChallengeProviderByName(config.DNSProvider)
	if err != nil {
		log.Fatal(err)
	}
	// Lego client
	client, err := lego.LegoClient(config.Certs.Email, provider, config.LegoDirectory)
	if err != nil {
		log.Fatal(err)
	}

	vaultClient, err := vault.NewVaultConnect(config.Vault)
	if err != nil {
		log.Fatal(err)
	}

	for {
		for i := range config.Certs.Domains {
			domain := config.Certs.Domains[i]
			log.Info("Проверяем домен ", domain)
			// Проверяем что сертификат не отсутвует или его срок менее 14 дней.
			valid := vault.CheckCertValid(vaultClient, domain, config.Vault.MountPath)
			if !valid {
				log.Debug("Сертификат ", domain, " требуется обновить.")
				certs, err := lego.GetCert(client, []string{domain})
				if err != nil {
					log.Error("Ошибка обновления сертификата ", err)
				}

				err = vault.WriteCert(vaultClient, config.Vault.MountPath, certs)
				if err != nil {
					log.Error("Ошибка записи секрета сертификата ", err)
				}
			}
			log.Debug("Сертификат ", domain, " обновлять не требуется.")

		}
		time.Sleep(60 * time.Minute)
	}

}
