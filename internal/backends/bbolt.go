package backends

import (
	"encoding/json"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

// VaultDB wraps a bolt.DB instance and manages user data.
type VaultDB struct {
	db *bolt.DB
}

// OpenVault opens (or creates) a vault database and ensures the "users" bucket exists.
func OpenVault(path string) (*VaultDB, error) {
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		return nil, err
	}

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("users"))
		return err
	})
	if err != nil {
		db.Close()
		return nil, err
	}

	return &VaultDB{db: db}, nil
}

// Close closes the underlying BoltDB.
func (v *VaultDB) Close() error {
	return v.db.Close()
}

// Add inserts or updates a user record.
func (v *VaultDB) Add(username, hash string, expire bool) error {
	expiration := int64(0)
	if expire {
		expiration = time.Now().AddDate(1, 0, 0).Unix() // 1 year
	}

	u := UserData{
		Hash:       hash,
		Expiration: expiration,
	}

	data, err := json.Marshal(u)
	if err != nil {
		return err
	}

	return v.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		return b.Put([]byte(username), data)
	})
}

// Search retrieves the stored hash and expiration for a given username.
func (v *VaultDB) Search(username string) (UserData, error) {
	var u UserData

	err := v.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		v := b.Get([]byte(username))
		if v == nil {
			return ErrUserNotFound
		}
		return json.Unmarshal(v, &u)
	})
	if err != nil {
		return u, err
	}

	return u, nil
}

// Cleanup removes expired users from the database.
func (v *VaultDB) Cleanup() error {
	return v.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		c := b.Cursor()

		for k, v := c.First(); k != nil; k, v = c.Next() {
			var u UserData
			if err := json.Unmarshal(v, &u); err != nil {
				continue
			}
			if u.Expiration != 0 && u.Expiration < time.Now().Unix() {
				if err := b.Delete(k); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func (v *VaultDB) ListUsers(search string, expiredOnly bool, offset, limit int) ([]User, int, error) {
	var users []User
	now := time.Now().Unix()
	err := v.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		return b.ForEach(func(k, v []byte) error {
			var u User
			if err := json.Unmarshal(v, &u); err != nil {
				return nil
			}
			u.Username = string(k)
			expired := u.Expiration != 0 && u.Expiration < now
			if search != "" && !strings.Contains(strings.ToLower(u.Username), strings.ToLower(search)) {
				return nil
			}
			if expiredOnly && !expired {
				return nil
			}
			users = append(users, u)
			return nil
		})
	})
	if err != nil {
		return nil, 0, err
	}
	total := len(users)
	if offset > total {
		return []User{}, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return users[offset:end], total, nil
}
