package quicstate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreatePersistsKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "reset.key")
	if err := os.Mkdir(filepathDir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	first, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
	second, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("key changed across reload")
	}
}

func TestLoadOrCreateRejectsMalformedKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reset.key")
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(path); err == nil {
		t.Fatal("expected malformed key failure")
	}
}

func TestValidateExistingDoesNotCreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.key")
	if err := ValidateExisting(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("check created a key")
	}
}

func TestLoadOrCreateDoesNotOverwriteConcurrentWinner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reset.key")
	type result struct {
		key [32]byte
		err error
	}
	results := make(chan result, 16)
	for i := 0; i < cap(results); i++ {
		go func() {
			key, err := LoadOrCreate(path)
			results <- result{key: [32]byte(key), err: err}
		}()
	}
	var key [32]byte
	for i := 0; i < cap(results); i++ {
		got := <-results
		if got.err != nil {
			t.Fatal(got.err)
		}
		if i > 0 && got.key != key {
			t.Fatal("concurrent loaders got different keys")
		}
		key = got.key
	}
	b, err := os.ReadFile(path)
	if err != nil || len(b) != ResetKeySize {
		t.Fatalf("final key length = %d, err = %v", len(b), err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("final mode = %v, err = %v", info.Mode().Perm(), err)
	}
	if matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".reset-key-*")); err != nil || len(matches) != 0 {
		t.Fatalf("temporary files = %v, err = %v", matches, err)
	}
}

func TestLoadOrCreatePreservesExistingWinner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reset.key")
	want := make([]byte, ResetKeySize)
	for i := range want {
		want[i] = byte(i)
	}
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 16; i++ {
		got, err := LoadOrCreate(path)
		if err != nil || string(got[:]) != string(want) {
			t.Fatalf("got existing key: err=%v", err)
		}
	}
}

func filepathDir(path string) string { return filepath.Dir(path) }
