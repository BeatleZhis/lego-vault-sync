package vault

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"BeatleZhis/lego-vault-sync/config"
	"BeatleZhis/lego-vault-sync/logging"

	log "github.com/sirupsen/logrus"

	"github.com/go-acme/lego/v4/certificate"
	vaultapi "github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

// CheckCertValid проверяет, что сертификат есть в Vault и до истечения срока
// действия осталось не меньше refreshDays дней. Любая проблема с чтением или
// разбором секрета считается поводом перевыпустить сертификат.
func CheckCertValid(client *vaultapi.Client, path string, mountPath string, refreshDays int) bool {
	ctx := context.Background()

	fields := log.Fields{
		"mount_path":  mountPath,
		"secret_path": path,
	}

	secret, err := client.Secrets.KvV2Read(ctx, path, vaultapi.WithMountPath(mountPath))
	if err != nil {
		log.WithError(err).WithFields(fields).Debug("сертификат не найден в Vault")
		return false
	}
	if secret == nil || secret.Data.Data == nil {
		log.WithFields(fields).Error("Vault вернул пустой секрет сертификата")
		return false
	}

	value, ok := secret.Data.Data["valid_to"].(string)
	if !ok {
		log.WithFields(fields).Error("в секрете нет поля valid_to")
		return false
	}

	validTo, err := time.Parse(time.RFC3339, value)
	if err != nil {
		log.WithError(err).WithField("valid_to", value).WithFields(fields).
			Error("не удалось разобрать срок действия сертификата")
		return false
	}

	days := int(time.Until(validTo).Hours() / 24)
	log.WithField("valid_to", validTo.UTC().Format(time.RFC3339)).
		WithField("days_left", days).
		WithFields(fields).
		Debug("срок действия сертификата в Vault")

	if days < refreshDays {
		log.WithField("days_left", days).
			WithField("refresh_days", refreshDays).
			WithFields(fields).
			Info("сертификат требует обновления")
		return false
	}

	return true
}

// WriteCert сохраняет выпущенный сертификат, ключ и CA в KV v2.
func WriteCert(client *vaultapi.Client, path string, mountPath string, certs *certificate.Resource) error {
	ctx := context.Background()

	block, _ := pem.Decode(certs.Certificate)
	if block == nil {
		return fmt.Errorf("не удалось разобрать PEM сертификата для %q", path)
	}

	certInfo, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("не удалось разобрать сертификат для %q: %w", path, err)
	}

	validTo := certInfo.NotAfter.UTC().Format(time.RFC3339)
	request := schema.KvV2WriteRequest{
		Data: map[string]any{
			"key":      string(certs.PrivateKey),
			"cert":     string(certs.Certificate),
			"ca":       string(certs.IssuerCertificate),
			"valid_to": validTo,
			"subject":  certInfo.Subject.CommonName,
		},
	}

	if _, err := client.Secrets.KvV2Write(ctx, path, request, vaultapi.WithMountPath(mountPath)); err != nil {
		return fmt.Errorf("не удалось записать секрет %q в Vault: %w", path, err)
	}

	log.WithFields(log.Fields{
		"mount_path":  mountPath,
		"secret_path": path,
		"subject":     certInfo.Subject.CommonName,
		"valid_to":    validTo,
	}).Info("сертификат сохранён в Vault")

	return nil
}

// NewVaultConnect создаёт клиент Vault и авторизуется в нём.
func NewVaultConnect(configVault config.VaultConfig) (*vaultapi.Client, error) {
	timeout := time.Duration(configVault.RequestTimeout) * time.Second
	if timeout <= 0 {
		timeout = config.DefaultRequestTimeoutSec * time.Second
	}

	// Начинаем с конфигурации по умолчанию и подменяем только нужные поля:
	// WithRetryConfiguration() затирает RetryMax/RetryWait*, если передать
	// его напрямую, поэтому настраиваем через WithConfiguration().
	clientConfig := vaultapi.DefaultConfiguration()
	clientConfig.Address = configVault.Address
	clientConfig.RequestTimeout = timeout
	clientConfig.RetryConfiguration.Logger = logging.VaultRetryLogger{}

	client, err := vaultapi.New(vaultapi.WithConfiguration(clientConfig))
	if err != nil {
		return nil, fmt.Errorf("не удалось инициализировать клиент Vault: %w", err)
	}

	ctx := context.Background()

	switch strings.ToLower(configVault.AuthType) {
	case "token":
		if configVault.Token == "" {
			return nil, errors.New("для авторизации по токену необходимо задать vault.token")
		}
		if err := client.SetToken(configVault.Token); err != nil {
			return nil, fmt.Errorf("не удалось установить токен Vault: %w", err)
		}
		log.WithField("auth_type", "token").Debug("авторизация в Vault выполнена")

	case "approle":
		if configVault.RoleID == "" || configVault.SecretID == "" {
			return nil, errors.New("для авторизации AppRole необходимо задать vault.roleID и vault.secretID")
		}

		resp, err := client.Write(ctx, "/auth/approle/login", map[string]any{
			"role_id":   configVault.RoleID,
			"secret_id": configVault.SecretID,
		})
		if err != nil {
			return nil, fmt.Errorf("не удалось авторизоваться в Vault через AppRole: %w", err)
		}
		if resp == nil || resp.Auth == nil {
			return nil, errors.New("Vault не вернул данные авторизации для AppRole")
		}
		if err := client.SetToken(resp.Auth.ClientToken); err != nil {
			return nil, fmt.Errorf("не удалось установить токен Vault: %w", err)
		}
		log.WithField("auth_type", "approle").Debug("авторизация в Vault выполнена")

	default:
		return nil, fmt.Errorf("неизвестный тип авторизации в Vault %q: ожидается %q или %q",
			configVault.AuthType, "token", "approle")
	}

	return client, nil
}
