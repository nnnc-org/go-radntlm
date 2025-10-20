package authapi

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nnnc-org/go-radntlm/internal/backends"
)

// --- Mock AuthStore ---

type mockAuthStore struct {
	users map[string]backends.UserData
	mu    sync.Mutex
}

func (m *mockAuthStore) Add(username, hash string, expire bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	exp := int64(0)
	if expire {
		exp = time.Now().Unix() - 100 // expired
	}
	m.users[username] = backends.UserData{Hash: hash, Expiration: exp}
	return nil
}

func (m *mockAuthStore) Search(username string) (backends.UserData, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ud, ok := m.users[username]
	if !ok {
		return backends.UserData{}, backends.ErrUserNotFound
	}
	return ud, nil
}

func (m *mockAuthStore) Cleanup() error { return nil }
func (m *mockAuthStore) Close() error   { return nil }

// --- Test authApiHandler ---

func TestAuthApiHandler_Unauthorized(t *testing.T) {
	handler := authApiHandler{
		token: "secrettoken",
		db:    &mockAuthStore{users: map[string]backends.UserData{}},
	}
	req := httptest.NewRequest("GET", "/authenticate", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", rr.Code)
	}
}

func TestAuthApiHandler_MissingParams(t *testing.T) {
	handler := authApiHandler{
		token: "token",
		db:    &mockAuthStore{users: map[string]backends.UserData{}},
	}
	req := httptest.NewRequest("GET", "/authenticate", nil)
	req.Header.Set("Authorization", "Bearer token")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request, got %d", rr.Code)
	}
}

func TestAuthApiHandler_UserNotFound(t *testing.T) {
	handler := authApiHandler{
		token: "token",
		db:    &mockAuthStore{users: map[string]backends.UserData{}},
	}
	//req := httptest.NewRequest("GET", "/authenticate?username=alice&nt-response=abc&challenge=def", nil)
	req := httptest.NewRequest("POST", "/authenticate", bytes.NewBufferString("username=alice&nt-response=abc&challenge=def"))
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Authentication failed") {
		t.Errorf("expected error message, got %q", rr.Body.String())
	}
}

func TestAuthApiHandler_Success(t *testing.T) {
	// Setup user with valid hash
	mockDB := &mockAuthStore{users: map[string]backends.UserData{
		"bob": {Hash: "8846f7eaee8fb117ad06bdd830b7586c", Expiration: 0},
	}}
	handler := authApiHandler{
		token: "token",
		db:    mockDB,
	}

	//req := httptest.NewRequest("GET", "/authenticate?username=bob&nt-response=dd5428b01e86f4dfcabeac394946dbd43ee88f794dd63255&challenge=0123456789abcdef", nil)
	req := httptest.NewRequest("POST", "/authenticate", bytes.NewBufferString("username=bob&nt-response=dd5428b01e86f4dfcabeac394946dbd43ee88f794dd63255&challenge=0123456789abcdef"))
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "NT_KEY: 166A9E32F11580C1C0B62F9CD0BDA633") {
		t.Errorf("expected NT_KEY in response, got %q", rr.Body.String())
	}
}

func TestStartServer_Shutdown(t *testing.T) {
	mockDB := &mockAuthStore{users: map[string]backends.UserData{}}
	token := "token"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := "127.0.0.1:0" // random port

	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	// Should not panic or block
	StartServer(ctx, addr, mockDB, token)
}

// --- Integration test for /authenticate endpoint ---

func TestAuthApiHandler_Integration(t *testing.T) {
	mockDB := &mockAuthStore{users: map[string]backends.UserData{
		"alice": {Hash: "8846f7eaee8fb117ad06bdd830b7586c", Expiration: 0},
	}}
	token := "token"
	handler := authApiHandler{
		token: token,
		db:    mockDB,
	}

	server := httptest.NewServer(handler)
	defer server.Close()

	url := fmt.Sprintf("%s/authenticate?username=alice&nt-response=dd5428b01e86f4dfcabeac394946dbd43ee88f794dd63255&challenge=0123456789abcdef", server.URL)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("http request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "NT_KEY: 166A9E32F11580C1C0B62F9CD0BDA633") {
		t.Errorf("expected NT_KEY in response, got %q", string(body))
	}
}
