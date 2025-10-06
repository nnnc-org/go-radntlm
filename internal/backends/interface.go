package backends

import (
	"errors"
	"time"
)

// UserData represents stored user credentials.
type UserData struct {
	Hash       string
	Expiration int64
}

// AuthStore defines a common interface for any credential backend.
type AuthStore interface {
	Add(username, hash string, expire bool) error
	Search(username string) (userData UserData, err error)
	Cleanup() error
	Close() error
}

// Define custom errors for the backends package
var ErrUserExpired = errors.New("password is expired")
var ErrUserNotFound = errors.New("user not found")

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
