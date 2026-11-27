package lego

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"
)

// memStore — хранилище состояния в памяти для тестов.
type memStore struct {
	mu     sync.Mutex
	states []*AccountState
}

func (m *memStore) LoadAccount(_ context.Context) (*AccountState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.states) == 0 {
		return nil, nil
	}
	return m.states[len(m.states)-1], nil
}

func (m *memStore) SaveAccount(_ context.Context, state *AccountState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.states = append(m.states, state)
	return nil
}

func (m *memStore) last() *AccountState {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.states) == 0 {
		return nil
	}
	return m.states[len(m.states)-1]
}

// nopProvider — DNS-провайдер, который никуда не ходит: challenge в тесте не запускается.
type nopProvider struct{}

func (nopProvider) Present(string, string, string) error { return nil }
func (nopProvider) CleanUp(string, string, string) error { return nil }

var _ challenge.Provider = nopProvider{}

// fakeACME — минимальный ACME-сервер (TLS: lego требует HTTPS по RFC 8555):
// отдаёт директорию и отвечает на new-acct так, как задано обработчиком,
// считая обращения.
type fakeACME struct {
	server *httptest.Server
	mu     sync.Mutex
	calls  int
}

func newFakeACME(t *testing.T, newAcct http.HandlerFunc) *fakeACME {
	t.Helper()

	f := &fakeACME{}
	mux := http.NewServeMux()
	f.server = httptest.NewTLSServer(mux)
	t.Cleanup(f.server.Close)

	// Доверяем самоподписанному сертификату тестового сервера через штатный
	// механизм lego (LEGO_CA_CERTIFICATES) — так же подключают корпоративный CA.
	certFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: f.server.Certificate().Raw,
	}), 0o600); err != nil {
		t.Fatalf("не удалось сохранить сертификат тестового CA: %v", err)
	}
	t.Setenv("LEGO_CA_CERTIFICATES", certFile)

	mux.HandleFunc("/directory", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"newAccount": f.server.URL + "/new-acct",
			"newNonce":   f.server.URL + "/new-nonce",
			"newOrder":   f.server.URL + "/new-order",
			"revokeCert": f.server.URL + "/revoke-cert",
			"keyChange":  f.server.URL + "/key-change",
			"meta":       map[string]string{"termsOfService": "https://example.com/tos"},
		})
	})
	mux.HandleFunc("/new-nonce", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce")
		w.WriteHeader(http.StatusOK)
	})
	mux.Handle("/new-acct", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.calls++
		f.mu.Unlock()
		newAcct(w, r)
	}))

	return f
}

func (f *fakeACME) newAccountCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeACME) directoryURL() string {
	return f.server.URL + "/directory"
}

// writeProblem отвечает problem+json с заданным статусом.
func writeProblem(w http.ResponseWriter, status int, problemType, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":   problemType,
		"detail": detail,
		"status": status,
	})
}

func TestLegoClientRateLimitKeepsKeyAndSuggestsRetryAfter(t *testing.T) {
	retryAt := time.Now().UTC().Add(2 * time.Hour).Format("2006-01-02 15:04:05 MST")
	ca := newFakeACME(t, func(w http.ResponseWriter, _ *http.Request) {
		writeProblem(w, http.StatusTooManyRequests, "urn:ietf:params:acme:error:rateLimited",
			"too many new registrations (10) from this IP address in the last 3h0m0s, retry after "+retryAt+
				": see https://letsencrypt.org/docs/rate-limits/#new-registrations-per-ip-address")
	})
	store := &memStore{}
	ctx := context.Background()
	acmeDir := ca.directoryURL()

	// Первая попытка: аккаунта нет, CA отвечает 429.
	_, err := legoClientWithDirectory(ctx, "test@example.com", nopProvider{}, "staging", acmeDir, store)
	if err == nil {
		t.Fatal("ожидалась ошибка rate limit")
	}
	if !strings.Contains(err.Error(), "не удалось зарегистрировать ACME-аккаунт") {
		t.Fatalf("неожиданная ошибка: %v", err)
	}

	// Из ошибки извлекается подсказка CA (~2h), которую main использует вместо бэкоффа.
	wait, ok := RetryAfter(err)
	if !ok || wait <= 90*time.Minute {
		t.Fatalf("RetryAfter: ok=%v wait=%v, ожидалось ~2h", ok, wait)
	}

	// Ключ сохранён ДО обращения к CA, регистрации нет.
	state := store.last()
	if state == nil || len(state.Key) == 0 {
		t.Fatal("ключ ACME-аккаунта не сохранён до регистрации")
	}
	firstKey := string(state.Key)
	if len(state.Registration) != 0 {
		t.Fatal("регистрация не должна была сохраниться при 429")
	}

	// Повторная попытка (следующая итерация main): используется тот же ключ.
	_, _ = legoClientWithDirectory(ctx, "test@example.com", nopProvider{}, "staging", acmeDir, store)
	state = store.last()
	if string(state.Key) != firstKey {
		t.Fatal("повторная попытка сгенерировала новый ключ — будут создаваться новые аккаунты")
	}
	if got := ca.newAccountCalls(); got != 2 {
		t.Fatalf("обращений к new-acct = %d, ожидалось 2", got)
	}
}

func TestLegoClientRegistersOnceWhenCARecovers(t *testing.T) {
	// Первые два обращения — 429, затем CA «выздоравливает» и создаёт аккаунт.
	retried := 0
	retryAt := time.Now().UTC().Add(time.Hour).Format("2006-01-02 15:04:05 MST")
	ca := newFakeACME(t, func(w http.ResponseWriter, _ *http.Request) {
		if retried < 2 {
			retried++
			writeProblem(w, http.StatusTooManyRequests, "urn:ietf:params:acme:error:rateLimited",
				"too many new registrations (10) from this IP address in the last 3h0m0s, retry after "+retryAt)
			return
		}
		w.Header().Set("Location", "http://acme.example/acct/1")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	})
	store := &memStore{}
	ctx := context.Background()
	acmeDir := ca.directoryURL()

	for i := 0; i < 2; i++ {
		if _, err := legoClientWithDirectory(ctx, "test@example.com", nopProvider{}, "staging", acmeDir, store); err == nil {
			t.Fatalf("попытка %d: ожидался rate limit", i+1)
		}
	}

	// После снятия лимита клиент готов, регистрация сохранена вместе с ключом.
	if _, err := legoClientWithDirectory(ctx, "test@example.com", nopProvider{}, "staging", acmeDir, store); err != nil {
		t.Fatalf("после снятия лимита клиент должен создаться: %v", err)
	}
	state := store.last()
	if state == nil || len(state.Registration) == 0 {
		t.Fatal("регистрация не сохранена после успешной регистрации")
	}
	if !strings.Contains(string(state.Registration), "/acct/1") {
		t.Fatalf("в регистрации нет URI аккаунта: %s", state.Registration)
	}
	if got := ca.newAccountCalls(); got != 3 {
		t.Fatalf("обращений к new-acct = %d, ожидалось 3", got)
	}
}
