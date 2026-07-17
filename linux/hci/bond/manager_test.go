package bond

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rigado/ble/linux/hci"
)

func testKey() []byte {
	return []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
}

const testAddr = "ffeeddccbbaa"

func TestSaveFindRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bonds.json")
	m := NewBondManager(path)

	bi := hci.NewBondInfo(testKey(), 0x1234, 0x56789abc, true)
	if err := m.Save(testAddr, bi); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if !m.Exists(testAddr) {
		t.Fatal("Exists returned false after Save")
	}

	got, err := m.Find(testAddr)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if string(got.LongTermKey()) != string(testKey()) {
		t.Fatalf("LongTermKey mismatch: got %x, want %x", got.LongTermKey(), testKey())
	}
	if got.EDiv() != 0x1234 {
		t.Fatalf("EDiv mismatch: got %x", got.EDiv())
	}
	if got.Random() != 0x56789abc {
		t.Fatalf("Random mismatch: got %x", got.Random())
	}
	if !got.Legacy() {
		t.Fatal("Legacy mismatch")
	}
}

func TestDelete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bonds.json")
	m := NewBondManager(path)

	bi := hci.NewBondInfo(testKey(), 0, 0, false)
	if err := m.Save(testAddr, bi); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := m.Delete(testAddr); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if m.Exists(testAddr) {
		t.Fatal("Exists returned true after Delete")
	}
	if err := m.Delete(testAddr); err == nil {
		t.Fatal("Delete of a missing bond should fail")
	}
}

// A read must not create the bond file as a side effect.
func TestReadDoesNotCreateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bonds.json")
	m := NewBondManager(path)

	if m.Exists(testAddr) {
		t.Fatal("Exists returned true for a missing file")
	}
	if _, err := m.Find(testAddr); err == nil {
		t.Fatal("Find should fail when no bond is stored")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("bond file was created by a read: stat err = %v", err)
	}
}

// A zero-length file (e.g. left behind by an interrupted write on older
// versions) is treated as an empty bond store and is recoverable via Save.
func TestEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bonds.json")
	if err := os.WriteFile(path, nil, 0644); err != nil {
		t.Fatal(err)
	}
	m := NewBondManager(path)

	if m.Exists(testAddr) {
		t.Fatal("Exists returned true for an empty file")
	}
	if err := m.Save(testAddr, hci.NewBondInfo(testKey(), 0, 0, false)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if !m.Exists(testAddr) {
		t.Fatal("Exists returned false after Save")
	}
}

// A corrupt bond file is quarantined so that subsequent Saves can recover;
// previously it made every load (and therefore every Save) fail forever.
func TestCorruptFileQuarantined(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bonds.json")
	if err := os.WriteFile(path, []byte(`{"truncated`), 0644); err != nil {
		t.Fatal(err)
	}
	m := NewBondManager(path)

	if m.Exists(testAddr) {
		t.Fatal("Exists returned true for a corrupt file")
	}
	if err := m.Save(testAddr, hci.NewBondInfo(testKey(), 0, 0, false)); err != nil {
		t.Fatalf("Save after corruption: %v", err)
	}
	if !m.Exists(testAddr) {
		t.Fatal("Exists returned false after Save")
	}

	quarantined, err := os.ReadFile(path + ".corrupt")
	if err != nil {
		t.Fatalf("quarantine file: %v", err)
	}
	if string(quarantined) != `{"truncated` {
		t.Fatalf("quarantine content mismatch: %q", quarantined)
	}
}

// Find deletes invalid entries but keeps the rest of the file intact.
func TestFindInvalidBondDeleted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bonds.json")
	content := `{"` + testAddr + `":{"longTermKey":"","encryptionDiversifier":"3412","randomValue":"0000000000000000","legacy":true},` +
		`"aaaaaaaaaaaa":{"longTermKey":"000102030405060708090a0b0c0d0e0f","encryptionDiversifier":"3412","randomValue":"0000000000000000","legacy":true}}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	m := NewBondManager(path)

	if _, err := m.Find(testAddr); err == nil || !strings.Contains(err.Error(), "invalid bondData") {
		t.Fatalf("Find of invalid bond: got err %v", err)
	}
	if m.Exists(testAddr) {
		t.Fatal("invalid bond should have been deleted")
	}
	if !m.Exists("aaaaaaaaaaaa") {
		t.Fatal("valid bond should have been kept")
	}
}

// Writes must not leave temporary files behind.
func TestNoTempFilesLeftBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bonds.json")
	m := NewBondManager(path)

	if err := m.Save(testAddr, hci.NewBondInfo(testKey(), 0, 0, false)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := m.Delete(testAddr); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "bonds.json" {
			t.Fatalf("unexpected file left behind: %s", e.Name())
		}
	}
}

// The default (relative) bond file path must work; this guards the
// filepath.Split handling in storeBonds.
func TestRelativePath(t *testing.T) {
	dir := t.TempDir()
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWd)

	m := NewBondManager("bonds.json")
	if err := m.Save(testAddr, hci.NewBondInfo(testKey(), 0, 0, false)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if !m.Exists(testAddr) {
		t.Fatal("Exists returned false after Save")
	}
}
