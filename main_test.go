package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/acme"
)

func TestNextInitRetryBackoff(t *testing.T) {
	// Обычная ошибка: пауза растёт экспоненциально 1m -> 2m -> 4m -> ...
	// и упирается в maxRetryDelay.
	err := fmt.Errorf("vault: connection refused")

	delay := initRetryDelay
	var waits []time.Duration
	for i := 0; i < 7; i++ {
		var wait time.Duration
		wait, delay = nextInitRetry(err, delay)
		waits = append(waits, wait)
	}

	want := []time.Duration{
		time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute,
		16 * time.Minute, 30 * time.Minute, 30 * time.Minute,
	}
	for i := range want {
		if waits[i] != want[i] {
			t.Fatalf("попытка %d: wait = %v, ожидалось %v (все паузы: %v)", i+1, waits[i], want[i], waits)
		}
	}
}

func TestNextInitRetryHonorsRetryAfter(t *testing.T) {
	// Rate limit: пауза берётся из подсказки CA (+ запас), бэкофф не растёт,
	// чтобы после снятия лимита серия началась с исходного интервала.
	retryAt := time.Now().UTC().Add(40 * time.Minute).Format("2006-01-02 15:04:05 MST")
	err := fmt.Errorf("не удалось зарегистрировать ACME-аккаунт: %w", &acme.ProblemDetails{
		Type:       acme.RateLimitedErr,
		HTTPStatus: 429,
		Detail:     "too many new registrations (10) from this IP address in the last 3h0m0s, retry after " + retryAt + ": see https://letsencrypt.org/docs/rate-limits/",
	})

	delay := 8 * time.Minute
	wait, next := nextInitRetry(err, delay)

	if wait <= 40*time.Minute || wait > 41*time.Minute+time.Second {
		t.Fatalf("wait = %v, ожидалось около 41m (40m + запас)", wait)
	}
	if next != delay {
		t.Fatalf("бэкофф не должен расти при retry after: next = %v, ожидалось %v", next, delay)
	}
}
