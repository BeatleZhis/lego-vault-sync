package vault

import (
	"context"
	"fmt"
	"net/http"
	"path"
	"strings"
	"time"

	"BeatleZhis/lego-vault-sync/lego"

	log "github.com/sirupsen/logrus"

	vaultapi "github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

// Поля секрета, в котором хранится состояние ACME-аккаунта.
const (
	accountKeyField          = "key"
	accountRegistrationField = "registration"
	accountUpdatedAtField    = "updated_at"
)

// AccountStore хранит состояние ACME-аккаунта в Vault KV v2.
//
// В Kubernetes файловая система пода эфемерна, поэтому ключ аккаунта и его
// регистрация лежат рядом с сертификатами и переживают рестарты пода.
type AccountStore struct {
	client    *vaultapi.Client
	mountPath string
	path      string
}

// NewAccountStore создаёт хранилище состояния ACME-аккаунта по пути path
// внутри KV v2-хранилища mountPath.
func NewAccountStore(client *vaultapi.Client, mountPath, path string) *AccountStore {
	return &AccountStore{
		client:    client,
		mountPath: strings.Trim(mountPath, "/ "),
		path:      strings.Trim(path, "/ "),
	}
}

// LoadAccount читает состояние аккаунта. Если секрета нет — возвращает (nil, nil).
func (s *AccountStore) LoadAccount(ctx context.Context) (*lego.AccountState, error) {
	secret, err := s.client.Secrets.KvV2Read(ctx, s.path, vaultapi.WithMountPath(s.mountPath))
	if err != nil {
		switch {
		case vaultapi.IsErrorStatus(err, http.StatusNotFound):
			log.WithField("secret_path", s.secretPath()).Debug("состояние ACME-аккаунта в Vault не найдено")
			return nil, nil

		case vaultapi.IsErrorStatus(err, http.StatusForbidden):
			return nil, fmt.Errorf(
				"нет прав на чтение состояния ACME-аккаунта %q: добавьте в политику Vault path %q с capabilities [\"read\", \"create\", \"update\"]: %w",
				s.secretPath(), s.policyPath(), err)

		default:
			return nil, fmt.Errorf("не удалось прочитать состояние ACME-аккаунта %q: %w", s.secretPath(), err)
		}
	}
	if secret == nil || secret.Data.Data == nil {
		return nil, fmt.Errorf("Vault вернул пустой секрет состояния ACME-аккаунта %q", s.secretPath())
	}

	key, ok := secret.Data.Data[accountKeyField].(string)
	if !ok || key == "" {
		return nil, fmt.Errorf("в секрете %q нет поля %q с ключом ACME-аккаунта",
			s.secretPath(), accountKeyField)
	}

	registration, _ := secret.Data.Data[accountRegistrationField].(string)

	return &lego.AccountState{
		Key:          []byte(key),
		Registration: []byte(registration),
	}, nil
}

// SaveAccount записывает состояние аккаунта в Vault.
func (s *AccountStore) SaveAccount(ctx context.Context, state *lego.AccountState) error {
	request := schema.KvV2WriteRequest{
		Data: map[string]any{
			accountKeyField:          string(state.Key),
			accountRegistrationField: string(state.Registration),
			accountUpdatedAtField:    time.Now().UTC().Format(time.RFC3339),
		},
	}

	if _, err := s.client.Secrets.KvV2Write(ctx, s.path, request, vaultapi.WithMountPath(s.mountPath)); err != nil {
		if vaultapi.IsErrorStatus(err, http.StatusForbidden) {
			return fmt.Errorf(
				"нет прав на запись состояния ACME-аккаунта %q: добавьте в политику Vault path %q с capabilities [\"read\", \"create\", \"update\"]: %w",
				s.secretPath(), s.policyPath(), err)
		}

		return fmt.Errorf("не удалось записать состояние ACME-аккаунта в %q: %w", s.secretPath(), err)
	}

	log.WithField("secret_path", s.secretPath()).Info("состояние ACME-аккаунта сохранено в Vault")

	return nil
}

// secretPath возвращает путь секрета в виде, удобном для логов и ошибок.
func (s *AccountStore) secretPath() string {
	return s.mountPath + "/data/" + s.path
}

// policyPath возвращает путь для политики Vault, покрывающий секреты
// состояния аккаунта всех окружений: <mount>/data/<accountPath>/*.
func (s *AccountStore) policyPath() string {
	parent := path.Dir(s.path)
	if parent == "." {
		parent = s.path
	}

	return s.mountPath + "/data/" + parent + "/*"
}
