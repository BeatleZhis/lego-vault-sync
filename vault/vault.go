package vault

import (
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

const refreshDays = 14

func CheckCertValid(client *vault.Client, path, mountPath string) bool {
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
			log.Fatal(err)
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

func NewVaultConnect(address, token string) (*vault.Client, error) {

	// prepare a client with the given base address
	client, err := vault.New(
		vault.WithAddress(address),
		vault.WithRequestTimeout(30*time.Second),
	)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	// authenticate with a root token (insecure)
	if err := client.SetToken(token); err != nil {
		log.Fatal(err)
		return nil, err
	}
	return client, nil
}
