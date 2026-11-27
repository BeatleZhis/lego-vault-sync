# lego-vault-sync

Инструмент для автоматического получения SSL-сертификатов (включая wildcard) через Lego и их сохранения в HashiCorp Vault с возможностью периодического обновления.

## 📋 Содержание
- [Конфигурация](#конфигурация)
- [Поддерживаемые DNS-провайдеры](#dns-провайдеры)
- [Настройка Vault](#vault)
- [Авторизация в Vault](#авторизация-в-vault)
  - [AppRole (рекомендуемый способ)](#approle-рекомендуемый-способ)
  - [Token (только для тестирования)](#token-только-для-тестирования)
- [Логи](#логи)

## Конфигурация

Пример конфигурационного файла находится в `config.example.yaml`. Для использования скопируйте его в `config.yaml` и настройте под свои нужды:

```bash
cp config.example.yaml config.yaml
```

| Ключ | По умолчанию | Описание |
|---|---|---|
| `DNSProvider` | — | Код DNS-провайдера lego (`regru`, `cloudflare`, `beget`, …) |
| `vault.address` | — | Адрес Vault |
| `vault.authType` | — | `approle` или `token` |
| `vault.roleID`, `vault.secretID` | — | Учётные данные AppRole (для `authType: approle`) |
| `vault.token` | — | Токен (для `authType: token`) |
| `vault.mountPath` | — | Путь KV v2 хранилища (например, `tls`) |
| `vault.certPath` | `""` | Префикс пути секрета внутри `mountPath` |
| `vault.requestTimeout` | `60` | Таймаут запроса к Vault, секунды |
| `certs.email` | — | Email для Let's Encrypt |
| `certs.domains` | — | Список доменов (wildcard — со звёздочкой) |
| `legoDirectory` | `staging` | `staging` или `production` |
| `vault.accountPath` | `<certPath>/acme-account` | Путь секрета с ключом и регистрацией ACME-аккаунта |
| `checkCertIntervalMin` | `600` | Интервал проверки сертификатов, минуты |
| `certRefreshIntervalDays` | `14` | За сколько дней до истечения обновлять сертификат |
| `logLevel` | `debug` | `debug`, `info`, `warn`, `error` |

Значения по умолчанию подставляются, если ключ не указан. Обязательные параметры проверяются при старте: при ошибке в конфигурации сервис завершается сразу, а не в середине цикла обновления.

⚠️ По умолчанию используется **staging** Let's Encrypt. Для боевых сертификатов явно укажите `legoDirectory: production`, иначе браузеры не будут доверять выпущенным сертификатам.

## DNS-провайдеры

Список поддерживаемых DNS-провайдеров доступен в [официальной документации Lego](https://go-acme.github.io/lego/dns/).

### Пример подключения провайдера

Для использования провайдера Regru:
1. Укажите его код `regru` в конфигурации
2. Добавьте необходимые переменные окружения согласно [документации Regru](https://go-acme.github.io/lego/dns/regru/)

```yaml
DNSProvider: regru
# Переменные окружения:
# REGRU_USERNAME, REGRU_PASSWORD
```

## Vault

### Настройка хранилища

Создайте secret engine в Vault для хранения сертификатов:

```bash
# Включение KV v2 хранилища по пути tls
vault secrets enable -path=tls kv-v2
```

### Структура хранения сертификатов

Для каждого домена создаётся отдельный секрет по пути:

```
<mountPath>/data/<certPath>/<domain>
```

Например, при `mountPath: tls` и пустом `certPath`:

`tls/data/example.com` — сертификат и ключ для example.com

`tls/data/*.example.com` — wildcard сертификат и ключ

Если указать `certPath: certs`, секреты будут лежать в `tls/data/certs/<domain>`.
Слэши в `certPath` нормализуются: значения `""`, `/` и `certs/` обрабатываются корректно и не приводят к двойным слэшам в запросах к Vault.

Каждый секрет содержит поля: `cert`, `key`, `ca`, `valid_to` (RFC3339), `subject`.

## Авторизация в Vault

Инструмент поддерживает два типа авторизации: `approle` и `token`.

### AppRole (рекомендуемый способ)

1. Включите авторизацию AppRole
```
vault auth enable approle
```
2. Создайте политику доступа:
```
echo 'path "tls/*" { capabilities = ["read", "list", "update", "create"] }' | vault policy write lego-tls-policy -
```
3. Создайте роль:
```
# Создание роли с привязанной политикой
vault write auth/approle/role/lego-approle token_policies="lego-tls-policy"

# Ограничение срока действия токена (опционально)
vault write auth/approle/role/lego-approle \
    token_policies="lego-tls-policy" \
    token_ttl=24h \
    token_max_ttl=168h
```
4. Получите учётные данные:

```
# Получение RoleID
vault read auth/approle/role/lego-approle/role-id

# Генерация SecretID
vault write -force auth/approle/role/lego-approle/secret-id
```

Настройка в config.yaml:

```yaml
vault:
  address: "https://vault.example.com:8800/"
  authType: approle
  roleID: aaabbbbb-cccc-dddd-eeee-ffff00001111
  secretID: 11111111-2222-3333-4444-555555555555
  mountPath: tls
  certPath: ""
  requestTimeout: 60
```

### Token (только для тестирования)
⚠️ Важно: Не используйте токен в production окружении! Только для тестирования и отладки.

Настройка в config.yaml:

```yaml
vault:
  address: "https://vault.example.com:8800/"
  authType: token
  token: "aaabbbbbcccc"
  mountPath: tls
  certPath: ""
  requestTimeout: 60
```

## Состояние ACME-аккаунта

Ключ и регистрация ACME-аккаунта хранятся **в Vault**, рядом с сертификатами — диск пода не используется и не нужен постоянный том:

```
tls/data/<accountPath>/staging      # ключ + регистрация для staging
tls/data/<accountPath>/production   # отдельный секрет для production
```

По умолчанию `accountPath` = `<certPath>/acme-account`, то есть ключ аккаунта лежит под тем же
префиксом, что и сертификаты. Например, при `mountPath: devops` и `certPath: tls/`:

```
devops/data/tls/example.com                  # сертификат
devops/data/tls/acme-account/production      # ключ и регистрация ACME-аккаунта
```

Так одна политика Vault на `devops/data/tls/*` покрывает и сертификаты, и состояние аккаунта.

Секрет содержит поля `key` (PEM-ключ аккаунта), `registration` (JSON регистрации) и `updated_at`.

- Ключ создаётся один раз и сохраняется в Vault **до** регистрации: если обращение к CA не удалось (в том числе из-за rate limit), повторные попытки используют тот же ключ — Let's Encrypt возвращает существующий аккаунт вместо создания нового, лимит регистраций не расходуется.
- При старте сохранённая регистрация проверяется на стороне CA. Повторная регистрация выполняется только когда CA уверенно сообщает об отсутствии аккаунта (`accountDoesNotExist`/404); при временных ошибках (сеть, 429, 5xx) попытка откладывается без изменения состояния.
- Ошибки инициализации (Vault недоступен, rate limit CA) **не завершают процесс**: сервис пишет ошибку в лог и повторяет попытку с экспоненциальным бэкоффом (от 1 минуты до 30 минут), а при 429 учитывает подсказку `retry after` из ответа Let's Encrypt. `/health` и `/metrics` доступны всё это время, поэтому оркестратор не рестартит под.
- Для `staging` и `production` используются разные секреты, поэтому окружения не пересекаются.
- Политика доступа к Vault должна включать чтение и запись этого пути. Политика из примера выше (`path "tls/*"`) покрывает и его; при более узких правах добавьте, например, `path "devops/data/tls/acme-account/*" { capabilities = ["read", "create", "update"] }`. При 403 сервис пишет в лог готовый путь для политики.
- Сервис рассчитан на одну реплику: при нескольких репликах одновременный выпуск сертификатов и запись состояния будут конфликтовать.

## Логи

Сервис пишет логи в stdout в формате JSON (logrus `JSONFormatter`), по одной записи на строку:

```json
{"level":"info","msg":"сертификат сохранён в Vault","mount_path":"tls","secret_path":"example.com","subject":"example.com","time":"2026-03-09T16:17:15+03:00","valid_to":"2026-06-07T13:17:15Z"}
```

- Уровень задаётся ключом `logLevel`.
- Полезные поля: `domain`, `secret_path`, `mount_path`, `days_left`, `valid_to`, `auth_type`.
- Логи сторонних библиотек тоже приводятся к JSON: записи стандартного логгера Go (`http.Server` и др.) получают поле `"src":"stdlib"`, HTTP-запросы к Vault — `"src":"vault/http"`, сообщения lego — `"src":"lego"`.

## Процесс работы

1. Проверка сертификатов — инструмент проверяет текущие сертификаты в Vault
2. Запрос новых сертификатов — при необходимости запрашивает новые через Lego
3. DNS-валидация — автоматическое подтверждение владения доменами через DNS-провайдера
4. Сохранение в Vault — обновлённые сертификаты сохраняются в Vault
5. Периодическое обновление — автоматическое обновление по расписанию
6. Graceful shutdown — по SIGINT/SIGTERM сервис завершает текущую итерацию и корректно останавливает HTTP-сервер
7. Ретраи без рестарта — если Vault или Let's Encrypt недоступны (в том числе rate limit при регистрации аккаунта), сервис продолжает работу: пишет ошибку в лог и повторяет инициализацию с бэкоффом

## Метрики

На порту `:8888` доступны:
- `/metrics` — метрики Prometheus (Go-процесс и `lvs_cert_update_errors{cert="<домен>"}`)
- `/health` — проверка живости

## Docker
Собрать в docker можно с помощью команды ```docker build . -t lego-vault-sync```

`config.yaml` монтируется в корень контейнера: `/config.yaml`.

Постоянный том не нужен: состояние ACME-аккаунта хранится в Vault.

```bash
docker run -v "$PWD/config.yaml:/config.yaml" lego-vault-sync
```

## FAQ
<details> <summary>Beget METHOD_FAILED: Failed to get DNS records</summary>

Beget не умеет отдавать данные по домену через API без предварительного создания требуемого поддомена `_acme-challenge.DOMAIN`.

Поэтому необходимо создать виртуальный поддомен:

```bash
curl  -X POST  -d 'login=<LOGIN>>&passwd=<PASSWORD>&input_format=json&input_data={"subdomain": "_acme-challenge","domain_id": <DOMAIN_ID>}' 'https://api.beget.com/api/domain/addSubdomainVirtual'
```

</details>
