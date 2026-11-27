package lego

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	legoapi "github.com/go-acme/lego/v4/lego"
	legolog "github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/registration"
	log "github.com/sirupsen/logrus"

	"BeatleZhis/lego-vault-sync/config"
)

// accountDoesNotExistErr — тип проблемы ACME, которым CA уверенно сообщает,
// что аккаунта с таким ключом/URI не существует (RFC 8555, §7.3.3).
const accountDoesNotExistErr = "urn:ietf:params:acme:error:accountDoesNotExist"

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
// постоянного диска. Ключ сохраняется в хранилище до регистрации: если
// обращение к CA не удалось (например, rate limit), повторные попытки
// используют тот же ключ, и CA возвращает существующий аккаунт вместо
// создания нового (RFC 8555, §7.3).
//
// Ошибки регистрации не считаются фатальными: вызывающий код повторяет
// попытку позже (см. RetryAfter).
func LegoClient(
	ctx context.Context,
	email string,
	dnsProvider challenge.Provider,
	legoDirectory string,
	store AccountStorage,
) (*Client, error) {
	directoryURL := legoapi.LEDirectoryStaging
	if legoDirectory == config.LegoDirectoryProduction {
		directoryURL = legoapi.LEDirectoryProduction
	}

	return legoClientWithDirectory(ctx, email, dnsProvider, legoDirectory, directoryURL, store)
}

// legoClientWithDirectory — реализация LegoClient с явно заданным URL ACME-
// директории (для тестов подставляется адрес фейкового CA).
func legoClientWithDirectory(
	ctx context.Context,
	email string,
	dnsProvider challenge.Provider,
	legoDirectory string,
	directoryURL string,
	store AccountStorage,
) (*Client, error) {
	legolog.Logger = legoLogger{}

	state, err := store.LoadAccount(ctx)
	if err != nil {
		return nil, fmt.Errorf("не удалось загрузить состояние ACME-аккаунта: %w", err)
	}

	var (
		privateKey crypto.Signer
		storedReg  *registration.Resource
		// encodedKey — PEM ключа, если он создан в этом вызове; нужен, чтобы
		// после регистрации сохранить в хранилище полное состояние.
		encodedKey []byte
	)

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

		encodedKey, err = encodeKey(privateKey)
		if err != nil {
			return nil, err
		}

		// Ключ сохраняется до обращения к CA: если регистрация сорвётся
		// (Vault или CA недоступны, rate limit), повторная попытка возьмёт
		// из хранилища тот же ключ и не создаст лишний аккаунт.
		if err := store.SaveAccount(ctx, &AccountState{Key: encodedKey}); err != nil {
			return nil, fmt.Errorf("не удалось сохранить ключ ACME-аккаунта: %w", err)
		}

		log.Info("сохранённый ACME-аккаунт не найден: ключ создан и сохранён, регистрируем")
	}

	myUser := &MyUser{
		Email:        email,
		key:          privateKey,
		Registration: storedReg,
	}

	legoConfig := legoapi.NewConfig(myUser)
	legoConfig.CADirURL = directoryURL

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
	// (аккаунт мог быть отозван или удалён). Повторная регистрация выполняется
	// только когда CA уверенно сообщает, что аккаунта нет; при временных
	// ошибках (сеть, rate limit) попытка откладывается, чтобы не создавать
	// лишние аккаунты и не расходовать лимит регистраций.
	if myUser.Registration != nil {
		if _, err := client.Registration.QueryRegistration(); err != nil {
			if !accountMissing(err) {
				return nil, fmt.Errorf("не удалось подтвердить сохранённый ACME-аккаунт у CA, повторим позже: %w", err)
			}
			log.WithError(err).Warn("сохранённый ACME-аккаунт отсутствует у CA, регистрируем заново")
			myUser.Registration = nil
		}
	}

	if myUser.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("не удалось зарегистрировать ACME-аккаунт, повторим позже: %w", err)
		}
		myUser.Registration = reg

		if encodedKey == nil {
			// Ключ загружен из хранилища, но регистрация там ещё не сохранена.
			encodedKey, err = encodeKey(privateKey)
			if err != nil {
				return nil, err
			}
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

// accountMissing сообщает, что CA уверенно ответил «аккаунта с таким
// ключом/URI нет» (accountDoesNotExist или 404). Остальные ошибки
// (сеть, rate limit, 5xx) считаются временными.
func accountMissing(err error) bool {
	var pd *acme.ProblemDetails
	if !errors.As(err, &pd) {
		return false
	}

	if pd.Type == accountDoesNotExistErr {
		return true
	}

	return pd.HTTPStatus == http.StatusNotFound
}

// retryAfterRe извлекает время повтора из текста ошибки rate limit
// Let's Encrypt: "... retry after 2026-11-27 06:04:48 UTC: ...".
var retryAfterRe = regexp.MustCompile(`retry after (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [A-Z]{2,5})`)

// RetryAfter возвращает, через сколько можно повторить запрос после ошибки
// rate limit (429). Время берётся из подсказки CA в тексте ошибки; если
// подсказки нет или она уже в прошлом, возвращает false.
func RetryAfter(err error) (time.Duration, bool) {
	var pd *acme.ProblemDetails
	if !errors.As(err, &pd) || pd.HTTPStatus != http.StatusTooManyRequests {
		return 0, false
	}

	match := retryAfterRe.FindStringSubmatch(pd.Detail)
	if match == nil {
		return 0, false
	}

	// Let's Encrypt указывает время в UTC. Для неизвестного Go сокращения
	// пояса time.Parse примет нулевое смещение — длительность будет неточной,
	// что для планирования повтора допустимо.
	ts, err := time.Parse("2006-01-02 15:04:05 MST", match[1])
	if err != nil {
		return 0, false
	}

	wait := time.Until(ts)
	if wait <= 0 {
		return 0, false
	}

	return wait, true
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
