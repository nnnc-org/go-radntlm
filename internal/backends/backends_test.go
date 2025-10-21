package backends

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// --- FlatfileDB Tests ---

func TestFlatfileDB_Add_Search(t *testing.T) {
	tmpfile := filepath.Join(os.TempDir(), "test_flatfile.txt")
	defer os.Remove(tmpfile)

	db, err := OpenFlatfile(tmpfile)
	if err != nil {
		t.Fatalf("OpenFlatfile failed: %v", err)
	}
	defer db.Close()

	err = db.Add("alice", "hash1", false)
	if err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	ud, err := db.Search("alice")
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	if ud.Hash != "hash1" {
		t.Errorf("expected hash1, got %s", ud.Hash)
	}
	if ud.Expiration != 0 {
		t.Errorf("expected expiration 0, got %d", ud.Expiration)
	}
}

func TestFlatfileDB_Add_Update(t *testing.T) {
	tmpfile := filepath.Join(os.TempDir(), "test_flatfile_update.txt")
	defer os.Remove(tmpfile)

	db, _ := OpenFlatfile(tmpfile)
	defer db.Close()

	db.Add("bob", "hash1", false)
	db.Add("bob", "hash2", true)

	ud, err := db.Search("bob")
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	if ud.Hash != "hash2" {
		t.Errorf("expected hash2, got %s", ud.Hash)
	}
	if ud.Expiration == 0 {
		t.Errorf("expected nonzero expiration")
	}
}

func TestFlatfileDB_Search_NotFound(t *testing.T) {
	tmpfile := filepath.Join(os.TempDir(), "test_flatfile_notfound.txt")
	defer os.Remove(tmpfile)

	db, _ := OpenFlatfile(tmpfile)
	defer db.Close()

	_, err := db.Search("nobody")
	if err != ErrUserNotFound {
		t.Errorf("expected ErrUserNotFound, got %v", err)
	}
}

func TestFlatfileDB_Cleanup(t *testing.T) {
	tmpfile := filepath.Join(os.TempDir(), "test_flatfile_cleanup.txt")
	defer os.Remove(tmpfile)

	db, _ := OpenFlatfile(tmpfile)
	defer db.Close()

	db.Add("old", "hash", true)
	db.Add("fresh", "hash", false)

	// Expire "old"
	lines, _ := db.readAllLines()
	lines[0] = "old:hash:1"
	db.writeAllLines(lines)

	err := db.Cleanup()
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}
	_, err = db.Search("old")
	if err != ErrUserNotFound {
		t.Errorf("expected old to be deleted, got %v", err)
	}
	_, err = db.Search("fresh")
	if err != nil {
		t.Errorf("expected fresh to remain, got %v", err)
	}
}

// --- VaultDB Tests ---

func TestVaultDB_Add_Search_Cleanup(t *testing.T) {
	tmpfile := filepath.Join(os.TempDir(), "test_vault.db")
	defer os.Remove(tmpfile)

	db, err := OpenVault(tmpfile)
	if err != nil {
		t.Fatalf("OpenVault failed: %v", err)
	}
	defer db.Close()

	err = db.Add("alice", "hash1", false)
	if err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	ud, err := db.Search("alice")
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	if ud.Hash != "hash1" {
		t.Errorf("expected hash1, got %s", ud.Hash)
	}

	// Add expired user
	db.Add("old", "hash2", false)
	// Manually expire
	db.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		u := UserData{Hash: "hash2", Expiration: 1}
		data, _ := json.Marshal(u)
		return b.Put([]byte("old"), data)
	})

	err = db.Cleanup()
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}
	_, err = db.Search("old")
	if err != ErrUserNotFound {
		t.Errorf("expected old to be deleted, got %v", err)
	}
}

// --- UserData/Interface Tests ---

func TestUserData_IsExpired(t *testing.T) {
	u := UserData{Expiration: 0}
	if u.IsExpired() {
		t.Error("should not be expired if Expiration is 0")
	}
	u.Expiration = time.Now().Unix() - 10
	if !u.IsExpired() {
		t.Error("should be expired if Expiration is in the past")
	}
	u.Expiration = time.Now().Unix() + 1000
	if u.IsExpired() {
		t.Error("should not be expired if Expiration is in the future")
	}
}

func TestAuthenticateUser_Valid(t *testing.T) {
	ntHash := "8846f7eaee8fb117ad06bdd830b7586c"
	challenge := "0123456789abcdef"
	ntResp := "dd5428b01e86f4dfcabeac394946dbd43ee88f794dd63255"

	// Mock AuthStore with correct hash
	mock := &mockAuthStore{
		users: map[string]UserData{
			"testuser": {Hash: ntHash, Expiration: 0},
		},
	}

	ntKey, err := AuthenticateUser(mock, "testuser", ntResp, challenge)
	if err != nil {
		t.Fatalf("AuthenticateUser failed: %v", err)
	}

	// The expected NT session key for this hash
	expectedKey := "166A9E32F11580C1C0B62F9CD0BDA633"
	if ntKey != expectedKey {
		t.Errorf("expected NT key %s, got %s", expectedKey, ntKey)
	}
}

func TestFlatfileDB_ListUsers(t *testing.T) {
	tmpfile := filepath.Join(os.TempDir(), "test_flatfile_listusers.txt")
	defer os.Remove(tmpfile)

	db, err := OpenFlatfile(tmpfile)
	if err != nil {
		t.Fatalf("OpenFlatfile failed: %v", err)
	}
	defer db.Close()

	now := time.Now().Unix()
	past := now - 10000

	// Add users
	db.Add("alice", "hash1", false)
	db.Add("bob", "hash2", false)
	db.Add("expired", "hash3", false)
	// Manually expire "expired"
	lines, _ := db.readAllLines()
	for i, line := range lines {
		if strings.HasPrefix(line, "expired:") {
			lines[i] = "expired:hash3:" + strconv.FormatInt(past, 10)
		}
	}
	db.writeAllLines(lines)

	// List all users
	users, total, err := db.ListUsers("", false, 0, 10)
	if err != nil {
		t.Fatalf("ListUsers failed: %v", err)
	}
	if total != 3 {
		t.Errorf("expected 3 users, got %d", total)
	}
	if len(users) != 3 {
		t.Errorf("expected 3 users in page, got %d", len(users))
	}

	// Search for "bob"
	users, total, err = db.ListUsers("bob", false, 0, 10)
	if total != 1 || len(users) != 1 || users[0].Username != "bob" {
		t.Errorf("search for bob failed: %+v", users)
	}

	// Filter expired
	users, total, err = db.ListUsers("", true, 0, 10)
	if total != 1 || len(users) != 1 || users[0].Username != "expired" {
		t.Errorf("filter expired failed: %+v", users)
	}

	// Pagination: page size 2
	users, total, err = db.ListUsers("", false, 0, 2)
	if len(users) != 2 {
		t.Errorf("expected 2 users in first page, got %d", len(users))
	}
	users2, _, _ := db.ListUsers("", false, 2, 2)
	if len(users2) != 1 {
		t.Errorf("expected 1 user in second page, got %d", len(users2))
	}
}

func TestVaultDB_ListUsers(t *testing.T) {
	tmpfile := filepath.Join(os.TempDir(), "test_vault_listusers.db")
	defer os.Remove(tmpfile)

	db, err := OpenVault(tmpfile)
	if err != nil {
		t.Fatalf("OpenVault failed: %v", err)
	}
	defer db.Close()

	now := time.Now().Unix()
	past := now - 10000

	// Add users
	db.Add("alice", "hash1", false)
	db.Add("bob", "hash2", false)
	db.Add("expired", "hash3", false)
	// Manually expire "expired"
	db.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		u := User{Username: "expired", Hash: "hash3", Expiration: past}
		data, _ := json.Marshal(u)
		return b.Put([]byte("expired"), data)
	})

	// List all users
	users, total, err := db.ListUsers("", false, 0, 10)
	if err != nil {
		t.Fatalf("ListUsers failed: %v", err)
	}
	if total != 3 {
		t.Errorf("expected 3 users, got %d", total)
	}
	if len(users) != 3 {
		t.Errorf("expected 3 users in page, got %d", len(users))
	}

	// Search for "alice"
	users, total, err = db.ListUsers("alice", false, 0, 10)
	if total != 1 || len(users) != 1 || users[0].Username != "alice" {
		t.Errorf("search for alice failed: %+v", users)
	}

	// Filter expired
	users, total, err = db.ListUsers("", true, 0, 10)
	if total != 1 || len(users) != 1 || users[0].Username != "expired" {
		t.Errorf("filter expired failed: %+v", users)
	}

	// Pagination: page size 2
	users, total, err = db.ListUsers("", false, 0, 2)
	if len(users) != 2 {
		t.Errorf("expected 2 users in first page, got %d", len(users))
	}
	users2, _, _ := db.ListUsers("", false, 2, 2)
	if len(users2) != 1 {
		t.Errorf("expected 1 user in second page, got %d", len(users2))
	}
}

// Minimal mockAuthStore for authenticateuser test
type mockAuthStore struct {
	users map[string]UserData
}

func (m *mockAuthStore) Add(username, hash string, expire bool) error { return nil }
func (m *mockAuthStore) Search(username string) (UserData, error) {
	ud, ok := m.users[username]
	if !ok {
		return UserData{}, ErrUserNotFound
	}
	return ud, nil
}
func (m *mockAuthStore) Cleanup() error { return nil }
func (m *mockAuthStore) Close() error   { return nil }
func (m *mockAuthStore) ListUsers(search string, expiredOnly bool, offset, limit int) ([]User, int, error) {
	return nil, 0, nil
}
