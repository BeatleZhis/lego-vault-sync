package lego

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/go-acme/lego/v4/registration"
)

// AccountState — состояние ACME-аккаунта, которое должно переживать рестарт
// пода: ключ аккаунта и (опционально) его регистрация у CA.
type AccountState struct {
	// Key — приватный ключ ACME-аккаунта в PEM.
	Key []byte
	// Registration — JSON регистрации (URI аккаунта). Может быть пустым,
	// если ключ сохранён, а регистрация ещё не выполнена.
	Registration []byte
}

// AccountStorage — хранилище состояния ACME-аккаунта вне контейнера.
//
// В Kubernetes диск пода эфемерный, поэтому состояние хранится в Vault
// (реализация — vault.AccountStore), а не в файловой системе.
type AccountStorage interface {
	// LoadAccount возвращает (nil, nil), если состояние ещё не сохранено.
	LoadAccount(ctx context.Context) (*AccountState, error)
	// SaveAccount создаёт или перезаписывает состояние.
	SaveAccount(ctx context.Context, state *AccountState) error
}

// encodeKey сериализует ключ ACME-аккаунта в PEM.
func encodeKey(key crypto.Signer) ([]byte, error) {
	var (
		der     []byte
		pemType = "PRIVATE KEY"
		err     error
	)

	if ecKey, ok := key.(*ecdsa.PrivateKey); ok {
		der, err = x509.MarshalECPrivateKey(ecKey)
		pemType = "EC PRIVATE KEY"
	} else {
		der, err = x509.MarshalPKCS8PrivateKey(key)
	}
	if err != nil {
		return nil, fmt.Errorf("не удалось сериализовать ключ ACME-аккаунта: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der}), nil
}

// parseKey разбирает ключ ACME-аккаунта из PEM.
func parseKey(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("ключ ACME-аккаунта не содержит PEM-блока")
	}

	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("ключ ACME-аккаунта не поддерживает подпись")
		}
		return signer, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("не удалось разобрать ключ ACME-аккаунта")
}

// encodeRegistration сериализует регистрацию ACME-аккаунта.
func encodeRegistration(reg *registration.Resource) ([]byte, error) {
	data, err := json.Marshal(reg)
	if err != nil {
		return nil, fmt.Errorf("не удалось сериализовать регистрацию ACME-аккаунта: %w", err)
	}

	return data, nil
}

// parseRegistration разбирает регистрацию ACME-аккаунта. Пустые данные
// означают, что аккаунт ещё не зарегистрирован.
func parseRegistration(data []byte) (*registration.Resource, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}

	var reg registration.Resource
	if err := json.Unmarshal(data, &reg); err != nil {
		return nil, fmt.Errorf("не удалось разобрать регистрацию ACME-аккаунта: %w", err)
	}

	return &reg, nil
}
