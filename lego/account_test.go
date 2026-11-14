package lego

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/go-acme/lego/v4/registration"
)

func TestKeyEncodeParseRoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("не удалось сгенерировать ключ: %v", err)
	}

	encoded, err := encodeKey(key)
	if err != nil {
		t.Fatalf("encodeKey: %v", err)
	}

	parsed, err := parseKey(encoded)
	if err != nil {
		t.Fatalf("parseKey: %v", err)
	}

	parsedEC, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("получен ключ типа %T, ожидался *ecdsa.PrivateKey", parsed)
	}

	wantDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	gotDER, err := x509.MarshalPKIXPublicKey(parsedEC.Public())
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	if !bytes.Equal(wantDER, gotDER) {
		t.Fatal("публичный ключ после сериализации и разбора изменился")
	}
}

func TestParseKeyRejectsGarbage(t *testing.T) {
	if _, err := parseKey([]byte("not a pem")); err == nil {
		t.Fatal("parseKey должен отвергать данные без PEM-блока")
	}
}

func TestRegistrationEncodeParseRoundTrip(t *testing.T) {
	want := &registration.Resource{URI: "https://acme.example/acct/42"}

	encoded, err := encodeRegistration(want)
	if err != nil {
		t.Fatalf("encodeRegistration: %v", err)
	}

	got, err := parseRegistration(encoded)
	if err != nil {
		t.Fatalf("parseRegistration: %v", err)
	}
	if got.URI != want.URI {
		t.Fatalf("URI = %q, ожидался %q", got.URI, want.URI)
	}
}

func TestParseRegistrationEmptyMeansMissing(t *testing.T) {
	for _, data := range [][]byte{nil, []byte(""), []byte("  \n")} {
		reg, err := parseRegistration(data)
		if err != nil {
			t.Fatalf("parseRegistration(%q): %v", data, err)
		}
		if reg != nil {
			t.Fatalf("parseRegistration(%q) вернул регистрацию, ожидался nil", data)
		}
	}
}

func TestParseRegistrationRejectsGarbage(t *testing.T) {
	if _, err := parseRegistration([]byte("{")); err == nil {
		t.Fatal("parseRegistration должен отвергать некорректный JSON")
	}
}
