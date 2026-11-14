package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"BeatleZhis/lego-vault-sync/config"
	"BeatleZhis/lego-vault-sync/lego"
	"BeatleZhis/lego-vault-sync/logging"
	"BeatleZhis/lego-vault-sync/vault"

	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

const (
	configPath      = "config.yaml"
	metricsAddr     = ":8888"
	shutdownTimeout = 10 * time.Second
)

func init() {
	logging.Setup()
}

func main() {
	if err := run(); err != nil {
		log.WithError(err).Error("сервис остановлен с ошибкой")
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	if err := logging.SetLevel(cfg.LogLevel); err != nil {
		return fmt.Errorf("неизвестный уровень логирования %q: %w", cfg.LogLevel, err)
	}

	log.WithFields(log.Fields{
		"dns_provider":        cfg.DNSProvider,
		"domains":             cfg.Certs.Domains,
		"check_interval":      (time.Duration(cfg.CheckCertIntervalMin) * time.Minute).String(),
		"refresh_before_days": cfg.CertRefreshIntervalDays,
		"vault_address":       cfg.Vault.Address,
		"mount_path":          cfg.Vault.MountPath,
		"auth_type":           cfg.Vault.AuthType,
		"lego_directory":      cfg.LegoDirectory,
		"account_secret_path": cfg.Vault.AccountSecretPath(cfg.LegoDirectory),
		"log_level":           cfg.LogLevel,
	}).Info("конфигурация загружена")

	registry := prometheus.NewRegistry()
	registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	certUpdateErrors := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "lvs_cert_update_errors",
			Help: "Количество ошибок выпуска и сохранения сертификатов по доменам.",
		},
		[]string{"cert"},
	)
	registry.MustRegister(certUpdateErrors)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if _, err := w.Write([]byte("ok")); err != nil {
			log.WithError(err).Debug("не удалось отправить ответ /health")
		}
	})

	server := &http.Server{
		Addr:              metricsAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Клиент Vault нужен до создания ACME-клиента: в Vault хранится состояние
	// аккаунта, поэтому диск пода не требуется.
	vaultClient, err := vault.NewVaultConnect(cfg.Vault)
	if err != nil {
		return fmt.Errorf("не удалось подключиться к Vault: %w", err)
	}

	accountStore := vault.NewAccountStore(
		vaultClient,
		cfg.Vault.MountPath,
		cfg.Vault.AccountSecretPath(cfg.LegoDirectory),
	)

	// DNS-провайдер настраивается переменными окружения (см. документацию lego).
	provider, err := dns.NewDNSChallengeProviderByName(cfg.DNSProvider)
	if err != nil {
		return fmt.Errorf("не удалось инициализировать DNS-провайдера %q: %w", cfg.DNSProvider, err)
	}

	legoClient, err := lego.LegoClient(ctx, cfg.Certs.Email, provider, cfg.LegoDirectory, accountStore)
	if err != nil {
		return err
	}

	serverErr := make(chan error, 1)
	go func() {
		log.WithField("addr", metricsAddr).Info("HTTP-сервер запущен")
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- fmt.Errorf("HTTP-сервер на %s завершился с ошибкой: %w", metricsAddr, err)
		}
	}()

	interval := time.Duration(cfg.CheckCertIntervalMin) * time.Minute
	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("получен сигнал остановки, завершаем работу")
			shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			defer cancel()
			if err := server.Shutdown(shutdownCtx); err != nil {
				return fmt.Errorf("не удалось корректно остановить HTTP-сервер: %w", err)
			}
			return nil

		case err := <-serverErr:
			return err

		case <-timer.C:
			checkAll(ctx, cfg, legoClient, certUpdateErrors)
			timer.Reset(interval)
		}
	}
}

// checkAll делает одну итерацию проверки всех доменов из конфигурации.
func checkAll(ctx context.Context, cfg config.Config, legoClient *lego.Client, updateErrors *prometheus.CounterVec) {
	// Клиент пересоздаётся на каждой итерации: это заодно продлевает
	// авторизацию AppRole, если TTL токена меньше интервала проверки.
	vaultClient, err := vault.NewVaultConnect(cfg.Vault)
	if err != nil {
		log.WithError(err).WithField("vault_address", cfg.Vault.Address).
			Error("не удалось подключиться к Vault, итерация проверки пропущена")
		return
	}

	for _, domain := range cfg.Certs.Domains {
		if ctx.Err() != nil {
			return
		}

		secretPath := cfg.Vault.SecretPath(domain)
		fields := log.Fields{
			"domain":      domain,
			"mount_path":  cfg.Vault.MountPath,
			"secret_path": secretPath,
		}

		log.WithFields(fields).Info("проверяем сертификат")

		if vault.CheckCertValid(vaultClient, secretPath, cfg.Vault.MountPath, cfg.CertRefreshIntervalDays) {
			log.WithFields(fields).Debug("сертификат обновлять не требуется")
			continue
		}

		certs, err := lego.GetCert(legoClient, []string{domain})
		if err != nil {
			log.WithError(err).WithFields(fields).Error("не удалось выпустить сертификат")
			updateErrors.WithLabelValues(domain).Inc()
			continue
		}

		if err := vault.WriteCert(vaultClient, secretPath, cfg.Vault.MountPath, certs); err != nil {
			log.WithError(err).WithFields(fields).Error("не удалось сохранить сертификат в Vault")
			updateErrors.WithLabelValues(domain).Inc()
			continue
		}

		log.WithFields(fields).Info("сертификат обновлён")
	}
}
