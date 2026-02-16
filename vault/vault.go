package vault

import (
	"BeatleZhis/lego-vault-sync/config"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

func CheckCertValid(client *vault.Client, path string, mountPath string, refreshDays int) bool {
	ctx := context.Background()
	secret, err := client.Secrets.KvV2Read(ctx, path, vault.WithMountPath(mountPath))
	if err != nil {
		log.Debug("Сертификат ", mountPath, "/", path, " не найден. ", err)
		return false
	}
	if value, ok := secret.Data.Data["valid_to"].(string); ok {
		log.Debug("Сертификат для домена  ", path, " действует до ", value)

		t, err := time.Parse(time.RFC3339, value)
		if err != nil {
			log.Error(err)
		}
		currentDate := time.Now().Truncate(24 * time.Hour)
		futureDate := t.Truncate(24 * time.Hour)

		// Вычисляем разницу в днях
		diff := futureDate.Sub(currentDate)
		days := int(diff.Hours() / 24)

		if days < refreshDays {
			log.Info("Требуется обновление сертификата срок действия: ", days, " дней.")
			return false
		}

		return true
	} else {
		log.Error("Ошибка получения данных о сроке действия сертификата.")
		return false
	}

}

func WriteCert(client *vault.Client, mountPath string, certs *certificate.Resource) error {
	ctx := context.Background()

	block, _ := pem.Decode(certs.Certificate)
	if block == nil {
		return fmt.Errorf("failed to parse PEM block")
	}
	certsinfo, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	schema := schema.KvV2WriteRequest{
		Data: map[string]any{
			"key":      string(certs.PrivateKey),
			"cert":     string(certs.Certificate),
			"ca":       string(certs.IssuerCertificate),
			"valid_to": certsinfo.NotAfter,
			"subject":  certsinfo.Subject.CommonName,
		}}

	_, ok := client.Secrets.KvV2Write(ctx, certs.Domain, schema, vault.WithMountPath(mountPath))
	if ok != nil {
		log.Fatal(ok)
		return ok
	}
	log.Println("secret written successfully")
	return nil
}

func NewVaultConnect(configVault config.VaultConfig) (*vault.Client, error) {

	// prepare a client with the given base address
	client, err := vault.New(
		vault.WithAddress(configVault.Address),
		vault.WithRequestTimeout(time.Duration(configVault.RequestTimeoutSec)*time.Second),
	)

	if err != nil {
		log.Fatal("unable to initialize vault client: %w", err)
		return nil, err
	}

	// Аутентификация в зависимости от типа
	switch configVault.AuthType {
	// Token
	case "token":
		if configVault.Token == "" {
			return nil, fmt.Errorf("token must be set for token auth")
		}
		if err := client.SetToken(configVault.Token); err != nil {
			return nil, fmt.Errorf("unable to set token: %w", err)
		}
		log.Debug("authenticated with token")
		// Approle
	case "approle":
		if configVault.RoleID == "" || configVault.SecretID == "" {
			return nil, fmt.Errorf("roleID and secretID must be set for approle auth")
		}

		// Создаем логин для AppRole
		loginData := map[string]interface{}{
			"role_id":   configVault.RoleID,
			"secret_id": configVault.SecretID,
		}

		// Выполняем логин
		ctx := context.Background()
		resp, err := client.Write(ctx, "/auth/approle/login", loginData)
		if err != nil {
			return nil, fmt.Errorf("unable to login with AppRole: %w", err)
		}

		if resp == nil || resp.Auth == nil {
			return nil, fmt.Errorf("no auth info returned from AppRole login")
		}

		// Устанавливаем полученный токен
		client.SetToken(resp.Auth.ClientToken)
		log.Debug("authenticated with AppRole")

	default:
		return nil, fmt.Errorf("unsupported auth type: %s", configVault.AuthType)
	}

	return client, nil
}
