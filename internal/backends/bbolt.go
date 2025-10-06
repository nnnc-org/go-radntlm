package backends

import (
	"encoding/json"
	"time"

	bolt "go.etcd.io/bbolt"
)

var VaultPath = "vault.db"
var Vault *bolt.DB

type UserData struct {
	Hash       string
	Expiration int64
}

func VaultInit(path string) error {
	if path != "" {
		VaultPath = path
	}

	var err error
	Vault, err = bolt.Open(VaultPath, 0600, nil)
	if err != nil {
		return err
	}
	defer Vault.Close()

	// make sure user bucket exists
	err = Vault.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("users"))
		return err
	})
	if err != nil {
		return err
	}
	return nil
}

func VaultSearch(username string) (string, int64, error) {
	var u UserData

	err := Vault.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		v := b.Get([]byte("username1"))
		return json.Unmarshal(v, &u)
	})
	if err != nil {
		return "", 0, err
	}

	return u.Hash, u.Expiration, nil
}

func VaultAdd(username, hash string, expire bool) error {
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

	err = Vault.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		return b.Put([]byte(username), data)
	})
	if err != nil {
		return err
	}
	return nil
}

func VaultCleanup() error {
	err := Vault.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		c := b.Cursor()

		for k, v := c.First(); k != nil; k, v = c.Next() {
			var u UserData
			err := json.Unmarshal(v, &u)
			if err != nil {
				continue
			}
			if u.Expiration != 0 && u.Expiration < time.Now().Unix() {
				err := b.Delete(k)
				if err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}
