package lego

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/acme"
)

func TestAccountMissing(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "accountDoesNotExist",
			err:  &acme.ProblemDetails{Type: accountDoesNotExistErr, HTTPStatus: 400},
			want: true,
		},
		{
			name: "404",
			err:  &acme.ProblemDetails{Type: "urn:ietf:params:acme:error:malformed", HTTPStatus: 404},
			want: true,
		},
		{
			name: "обёрнутая accountDoesNotExist",
			err:  fmt.Errorf("не удалось подтвердить аккаунт: %w", &acme.ProblemDetails{Type: accountDoesNotExistErr}),
			want: true,
		},
		{
			name: "rate limit",
			err:  &acme.ProblemDetails{Type: acme.RateLimitedErr, HTTPStatus: 429},
			want: false,
		},
		{
			name: "5xx",
			err:  &acme.ProblemDetails{HTTPStatus: 500},
			want: false,
		},
		{
			name: "не acme-ошибка",
			err:  errors.New("connection refused"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := accountMissing(tt.err); got != tt.want {
				t.Fatalf("accountMissing(%v) = %v, ожидалось %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestRetryAfter(t *testing.T) {
	rateLimited := func(detail string) error {
		return fmt.Errorf("не удалось зарегистрировать ACME-аккаунт: %w", &acme.ProblemDetails{
			Type:       acme.RateLimitedErr,
			HTTPStatus: 429,
			Detail:     detail,
		})
	}

	t.Run("подсказка из текста ошибки", func(t *testing.T) {
		retryAt := time.Now().UTC().Add(17 * time.Minute)
		err := rateLimited(fmt.Sprintf(
			"too many new registrations (10) from this IP address in the last 3h0m0s, retry after %s: see https://letsencrypt.org/docs/rate-limits/",
			retryAt.Format("2006-01-02 15:04:05 MST"),
		))

		wait, ok := RetryAfter(err)
		if !ok {
			t.Fatal("RetryAfter не распознал подсказку retry after")
		}
		if wait <= 15*time.Minute || wait > 17*time.Minute {
			t.Fatalf("wait = %v, ожидалось около 17m", wait)
		}
	})

	t.Run("не 429", func(t *testing.T) {
		if _, ok := RetryAfter(&acme.ProblemDetails{HTTPStatus: 500, Detail: "retry after 2030-01-01 00:00:00 UTC"}); ok {
			t.Fatal("RetryAfter должен игнорировать не-429 ошибки")
		}
	})

	t.Run("429 без подсказки", func(t *testing.T) {
		if _, ok := RetryAfter(rateLimited("too many pending authorizations")); ok {
			t.Fatal("RetryAfter не должен выдумывать время без подсказки")
		}
	})

	t.Run("подсказка в прошлом", func(t *testing.T) {
		past := time.Now().UTC().Add(-time.Minute).Format("2006-01-02 15:04:05 MST")
		if _, ok := RetryAfter(rateLimited("too many new registrations, retry after " + past)); ok {
			t.Fatal("RetryAfter не должен возвращать прошедшее время")
		}
	})
}
