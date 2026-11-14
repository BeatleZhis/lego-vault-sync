package lego

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	legoapi "github.com/go-acme/lego/v4/lego"
	legolog "github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/registration"
	log "github.com/sirupsen/logrus"

	"BeatleZhis/lego-vault-sync/config"
)

// Client — алиас ACME-клиента lego, чтобы им можно было пользоваться
// из других пакетов проекта, не импортируя библиотеку lego напрямую.
type Client = legoapi.Client

// legoLogger перенаправляет логи библиотеки lego в logrus, чтобы они
// попадали в общий JSON-поток, а не в plain-text stderr.
type legoLogger struct{}

func (legoLogger) Print(args ...any)   { log.WithField("src", "lego").Debug(args...) }
func (legoLogger) Println(args ...any) { log.WithField("src", "lego").Debugln(args...) }
func (legoLogger) Printf(format string, args ...any) {
	log.WithField("src", "lego").Debugf(format, args...)
}
func (legoLogger) Fatal(args ...any)   { log.WithField("src", "lego").Fatal(args...) }
func (legoLogger) Fatalln(args ...any) { log.WithField("src", "lego").Fatalln(args...) }
func (legoLogger) Fatalf(format string, args ...any) {
	log.WithField("src", "lego").Fatalf(format, args...)
}

// MyUser реализует registration.User для lego.
type MyUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *MyUser) GetEmail() string                        { return u.Email }
func (u *MyUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *MyUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// LegoClient создаёт ACME-клиента, восстанавливает или регистрирует аккаунт
// и настраивает DNS-01 валидацию через переданного провайдера.
//
// Ключ и регистрация аккаунта загружаются из AccountStorage (в Kubernetes —
// Vault), поэтому рестарты пода не создают новых ACME-аккаунтов и не требуют
// постоянного диска.
func LegoClient(
	ctx context.Context,
	email string,
	dnsProvider challenge.Provider,
	legoDirectory string,
	store AccountStorage,
) (*Client, error) {
	legolog.Logger = legoLogger{}

	state, err := store.LoadAccount(ctx)
	if err != nil {
		return nil, fmt.Errorf("не удалось загрузить состояние ACME-аккаунта: %w", err)
	}

	var privateKey crypto.Signer
	var storedReg *registration.Resource

	if state != nil && len(state.Key) > 0 {
		privateKey, err = parseKey(state.Key)
		if err != nil {
			return nil, fmt.Errorf("не удалось разобрать сохранённый ключ ACME-аккаунта: %w", err)
		}

		storedReg, err = parseRegistration(state.Registration)
		if err != nil {
			return nil, err
		}

		log.WithFields(log.Fields{
			"account_uri": accountURI(storedReg),
		}).Info("загружено сохранённое состояние ACME-аккаунта")
	} else {
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("не удалось сгенерировать ключ ACME-аккаунта: %w", err)
		}

		log.Info("сохранённый ACME-аккаунт не найден, создаём новый")
	}

	myUser := &MyUser{
		Email:        email,
		key:          privateKey,
		Registration: storedReg,
	}

	legoConfig := legoapi.NewConfig(myUser)

	if legoDirectory == config.LegoDirectoryProduction {
		legoConfig.CADirURL = legoapi.LEDirectoryProduction
	} else {
		legoConfig.CADirURL = legoapi.LEDirectoryStaging
	}

	log.WithFields(log.Fields{
		"email":          email,
		"acme_directory": legoConfig.CADirURL,
	}).Info("создаём ACME-клиента")

	if legoDirectory != config.LegoDirectoryProduction {
		log.Warn("используется staging-окружение Let's Encrypt: выпущенные сертификаты не являются доверенными")
	}

	client, err := legoapi.NewClient(legoConfig)
	if err != nil {
		return nil, fmt.Errorf("не удалось создать клиента lego: %w", err)
	}

	// Проверяем, что сохранённая регистрация ещё действительна на стороне CA
	// (аккаунт мог быть отозван или удалён).
	if myUser.Registration != nil {
		if _, err := client.Registration.QueryRegistration(); err != nil {
			log.WithError(err).Warn("сохранённый ACME-аккаунт не подтверждён CA, регистрируем заново")
			myUser.Registration = nil
		}
	}

	if myUser.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("не удалось зарегистрировать ACME-аккаунт: %w", err)
		}
		myUser.Registration = reg

		encodedKey, err := encodeKey(privateKey)
		if err != nil {
			return nil, err
		}
		encodedReg, err := encodeRegistration(reg)
		if err != nil {
			return nil, err
		}

		if err := store.SaveAccount(ctx, &AccountState{Key: encodedKey, Registration: encodedReg}); err != nil {
			return nil, fmt.Errorf("не удалось сохранить состояние ACME-аккаунта: %w", err)
		}

		log.WithField("account_uri", reg.URI).Info("ACME-аккаунт зарегистрирован и сохранён")
	}

	if err := client.Challenge.SetDNS01Provider(dnsProvider); err != nil {
		return nil, fmt.Errorf("не удалось включить DNS-01 challenge: %w", err)
	}

	log.WithField("account_uri", myUser.Registration.URI).Info("ACME-клиент готов")

	return client, nil
}

// accountURI возвращает URI аккаунта или пустую строку, если регистрации нет.
func accountURI(reg *registration.Resource) string {
	if reg == nil {
		return ""
	}

	return reg.URI
}

// GetCert выпускает новый сертификат для указанных доменов.
func GetCert(client *Client, domains []string) (*certificate.Resource, error) {
	log.WithField("domains", domains).Info("запрашиваем сертификат в ACME")

	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}

	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return nil, fmt.Errorf("не удалось выпустить сертификат для %v: %w", domains, err)
	}

	return certificates, nil
}
