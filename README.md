# lego-vault-sync

Инструмент для автоматического получения SSL-сертификатов (включая wildcard) через Lego и их сохранения в HashiCorp Vault с возможностью периодического обновления.

## 📋 Содержание
- [Конфигурация](#конфигурация)
- [Поддерживаемые DNS-провайдеры](#dns-провайдеры)
- [Настройка Vault](#vault)
- [Авторизация в Vault](#авторизация-в-vault)
  - [AppRole (рекомендуемый способ)](#approle-рекомендуемый-способ)
  - [Token (только для тестирования)](#token-только-для-тестирования)

## Конфигурация

Пример конфигурационного файла находится в `config.example.yaml`. Для использования скопируйте его в `config.yaml` и настройте под свои нужды:

```bash
cp config.example.yaml config.yaml
```

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

Структура хранения сертификатов.

Для каждого домена создаются отдельные секреты:

`tls/data/example.com` - содержит сертификат и ключ для example.com

`tls/data/*.example.com` - содержит wildcard сертификат и ключ

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
4. Получите учетные данные:

```
# Получение RoleID
vault read auth/approle/role/lego-approle/role-id

# Генерация SecretID
vault write -force auth/approle/role/lego-approle/secret-id```
```
Настройка в config.yaml:

```yaml
vault:
  address: "https://vault.example.com:8800/"
  authType: approle
  roleID: aaabbbbbcccc
  secretID: 111111111222
  mountPath: tls
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
  certPath: / 
  requestTimeout: 60
```

# Процесс работы

1. Проверка сертификатов - инструмент проверяет текущие сертификаты в Vault
2. Запрос новых сертификатов - при необходимости запрашивает новые через Lego
3. DNS-валидация - автоматическое подтверждение владения доменами через DNS-провайдера
4. Сохранение в Vault - обновленные сертификаты сохраняются в Vault
5. Периодическое обновление - автоматическое обновление по расписанию

# Docker
Собрать в docker можно с помощью команды ```docker build . -t lego-vault-sync```

# FAQ
<details> <summary>Beget METHOD_FAILED: Failed to get DNS records</summary>

Beget не умеет отдавать данные по домену через API без предварительного создания требуемого поддомена `_acme-challenge.DOMAIN`.

Поэтому необходимо создать виртуальный поддомен:

```bash
curl  -X POST  -d 'login=<LOGIN>>&passwd=<PASSWORD>&input_format=json&input_data={"subdomain": "_acme-challenge","domain_id": <DOMAIN_ID>}' 'https://api.beget.com/api/domain/addSubdomainVirtual'
```

</details>