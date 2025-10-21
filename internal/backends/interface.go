package backends

import (
	"errors"
	"time"

	"github.com/nnnc-org/go-radntlm/internal/crypto"
)

// UserData represents stored user credentials.
type UserData struct {
	Hash       string
	Expiration int64
}

// User represents a user record in the backend.
type User struct {
	Username   string
	Hash       string
	Expiration int64
}

// AuthStore defines a common interface for any credential backend.
type AuthStore interface {
	Add(username, hash string, expire bool) error
	Search(username string) (userData UserData, err error)
	ListUsers(search string, expiredOnly bool, offset, limit int) ([]User, int, error)
	Cleanup() error
	Close() error
}

// Define custom errors for the backends package
var ErrUserExpired = errors.New("password is expired")
var ErrUserNotFound = errors.New("user not found")
var ErrEmptyHash = errors.New("empty hash for user")
var ErrIncorrectPassword = errors.New("incorrect password")

func Init(filePath string, dbPath string) (AuthStore, error) {
	if filePath != "" && dbPath != "" {
		return nil, errors.New("cannot use both flatfile and db backends simultaneously")
	}

	if filePath != "" {
		db, err := OpenFlatfile(filePath)
		if err != nil {
			return nil, err
		}
		return db, nil
	} else if dbPath != "" {
		db, err := OpenVault(dbPath)
		if err != nil {
			return nil, err
		}
		return db, nil
	}

	return nil, errors.New("no backend specified")
}

func (u *UserData) IsExpired() bool {
	if u.Expiration == 0 {
		return false
	}
	return u.Expiration < time.Now().Unix()
}

// returns NT_KEY if authentication is successful
func AuthenticateUser(db AuthStore, username, ntResponse, challenge string) (string, error) {
	ud, err := db.Search(username)
	if err != nil {
		return "", err
	}

	if ud.Hash == "" {
		return "", ErrEmptyHash
	}

	if ud.IsExpired() {
		return "", ErrUserExpired
	}

	valid, err := crypto.ValidateNTResponse(ntResponse, challenge, ud.Hash)
	if err != nil {
		return "", err
	}

	if valid {
		// return nt key
		ntKey := crypto.CreateNTSessionKey(ud.Hash)
		return ntKey, nil
	} else {
		return "", ErrIncorrectPassword
	}
}
