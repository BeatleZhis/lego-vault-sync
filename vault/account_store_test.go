package vault

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"BeatleZhis/lego-vault-sync/lego"
	"BeatleZhis/lego-vault-sync/logging"

	log "github.com/sirupsen/logrus"

	vaultapi "github.com/hashicorp/vault-client-go"
)

// fakeKV — минимальная заглушка Vault KV v2: хранит data по путям запросов.
type fakeKV struct {
	mu   sync.Mutex
	data map[string]map[string]any
}

func newFakeKV() *fakeKV {
	return &fakeKV{data: make(map[string]map[string]any)}
}

func (f *fakeKV) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	switch r.Method {
	case http.MethodGet:
		data, ok := f.data[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":[]}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"data":     data,
				"metadata": map[string]any{"version": 1},
			},
		})

	case http.MethodPost, http.MethodPut:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var payload struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		f.data[r.URL.Path] = payload.Data
		w.WriteHeader(http.StatusNoContent)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func newTestStore(t *testing.T, fake *fakeKV) *AccountStore {
	t.Helper()

	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)

	clientConfig := vaultapi.DefaultConfiguration()
	clientConfig.Address = server.URL
	clientConfig.RequestTimeout = 0
	clientConfig.RetryConfiguration.RetryMax = 0
	clientConfig.RetryConfiguration.Logger = logging.VaultRetryLogger{}

	client, err := vaultapi.New(vaultapi.WithConfiguration(clientConfig))
	if err != nil {
		t.Fatalf("не удалось создать клиент Vault: %v", err)
	}

	return NewAccountStore(client, "tls", "acme-account/staging")
}

func silenceLogs(t *testing.T) {
	t.Helper()

	previous := log.GetLevel()
	log.SetLevel(log.PanicLevel)
	t.Cleanup(func() { log.SetLevel(previous) })
}

func TestAccountStoreLoadMissingReturnsNil(t *testing.T) {
	silenceLogs(t)

	store := newTestStore(t, newFakeKV())

	state, err := store.LoadAccount(context.Background())
	if err != nil {
		t.Fatalf("LoadAccount: %v", err)
	}
	if state != nil {
		t.Fatalf("LoadAccount вернул %+v, ожидался nil", state)
	}
}

func TestAccountStoreRoundTrip(t *testing.T) {
	silenceLogs(t)

	store := newTestStore(t, newFakeKV())
	ctx := context.Background()

	want := &lego.AccountState{
		Key:          []byte("-----BEGIN EC PRIVATE KEY-----\nkey\n-----END EC PRIVATE KEY-----\n"),
		Registration: []byte(`{"uri":"https://acme.example/acct/1"}`),
	}

	if err := store.SaveAccount(ctx, want); err != nil {
		t.Fatalf("SaveAccount: %v", err)
	}

	got, err := store.LoadAccount(ctx)
	if err != nil {
		t.Fatalf("LoadAccount: %v", err)
	}
	if string(got.Key) != string(want.Key) {
		t.Fatalf("ключ после round-trip изменился")
	}
	if string(got.Registration) != string(want.Registration) {
		t.Fatalf("регистрация после round-trip изменилась: %q", got.Registration)
	}
}

func TestAccountStoreRejectsSecretWithoutKey(t *testing.T) {
	silenceLogs(t)

	fake := newFakeKV()
	fake.data["/v1/tls/data/acme-account/staging"] = map[string]any{"registration": "{}"}

	store := newTestStore(t, fake)

	if _, err := store.LoadAccount(context.Background()); err == nil {
		t.Fatal("LoadAccount должен вернуть ошибку для секрета без ключа")
	}
}

func TestAccountSecretPath(t *testing.T) {
	store := NewAccountStore(nil, "tls", "acme-account/staging")

	if got, want := store.secretPath(), "tls/data/acme-account/staging"; got != want {
		t.Fatalf("secretPath() = %q, ожидался %q", got, want)
	}
}
