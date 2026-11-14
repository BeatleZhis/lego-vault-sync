// Package logging настраивает единый JSON-вывод логов приложения.
//
// logrus сам по себе пишет JSON, но сторонние библиотеки (retryablehttp внутри
// vault-client-go, http.Server, lego) используют собственные логгеры поверх
// стандартного пакета log и пишут plain-text в stderr. Пакет перенаправляет
// такие записи в общий JSON-поток.
package logging

import (
	stdlog "log"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// Setup включает JSON-формат logrus и перехватывает вывод стандартного
// логгера Go. Вызывать один раз при старте приложения.
func Setup() {
	log.SetFormatter(&log.JSONFormatter{TimestampFormat: time.RFC3339})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)

	// Стандартный логгер пишет в stderr с префиксом даты — убираем его,
	// чтобы в JSON не попадали дублирующие таймстемпы.
	stdlog.SetFlags(0)
	stdlog.SetOutput(StdWriter{})
}

// SetLevel устанавливает уровень логирования по имени (debug, info, warn, error).
func SetLevel(level string) error {
	parsed, err := log.ParseLevel(level)
	if err != nil {
		return err
	}
	log.SetLevel(parsed)
	return nil
}

// StdWriter перенаправляет записи стандартного логгера Go в logrus.
type StdWriter struct{}

// Write реализует io.Writer: каждая строка stdlib-лога становится
// отдельной JSON-записью с полем src=stdlib.
func (StdWriter) Write(p []byte) (int, error) {
	for _, line := range strings.Split(strings.TrimRight(string(p), "\r\n"), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			log.WithField("src", "stdlib").Info(line)
		}
	}
	return len(p), nil
}

// VaultRetryLogger реализует интерфейс retryablehttp.Logger, который
// vault-client-go передаёт во внутренний HTTP-клиент. Без него все запросы
// и повторы к Vault печатались бы в stderr как "[DEBUG] GET https://...".
type VaultRetryLogger struct{}

// Printf пишет сообщение о запросе/повторе в Vault в debug-уровне.
func (VaultRetryLogger) Printf(format string, args ...any) {
	log.WithField("src", "vault/http").Debugf(format, args...)
}
