package backends

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// FlatfileDB wraps access to a flat file user database.
type FlatfileDB struct {
	path string
}

// OpenFlatfile opens (or creates) a flatfile database at the given path.
func OpenFlatfile(path string) (*FlatfileDB, error) {
	// Ensure file exists (creates if missing)
	f, err := os.OpenFile(path, os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}
	f.Close()

	return &FlatfileDB{path: path}, nil
}

// Add appends or updates a user record in the flatfile.
// Format per line: username:hash:expiration
func (db *FlatfileDB) Add(username, hash string, expire bool) error {
	expiration := int64(0)
	if expire {
		expiration = time.Now().AddDate(1, 0, 0).Unix() // 1 year
	}

	// First read all lines and rewrite if username exists
	lines, err := db.readAllLines()
	if err != nil {
		return err
	}

	found := false
	for i, line := range lines {
		if strings.HasPrefix(line, username+":") {
			lines[i] = fmt.Sprintf("%s:%s:%d", username, hash, expiration)
			found = true
			break
		}
	}

	if !found {
		lines = append(lines, fmt.Sprintf("%s:%s:%d", username, hash, expiration))
	}

	return db.writeAllLines(lines)
}

// Search looks up a username in the flatfile and returns its hash and expiration.
func (db *FlatfileDB) Search(username string) (UserData, error) {
	ud := UserData{}

	file, err := os.Open(db.path)
	if err != nil {
		return ud, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, username+":") {
			parts := strings.SplitN(line, ":", 3)
			if len(parts) < 3 {
				return ud, fmt.Errorf("invalid line format for user '%s'", username)
			}

			expiration := int64(0)
			expStr := strings.TrimSpace(parts[2])
			if expStr != "" {
				expiration, err = strconv.ParseInt(expStr, 10, 64)
				if err != nil {
					return ud, fmt.Errorf("invalid expiration '%s' for user '%s'", expStr, username)
				}
			}

			ud = UserData{
				Hash:       strings.TrimSpace(parts[1]),
				Expiration: expiration,
			}
			return ud, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return ud, err
	}

	return ud, ErrUserNotFound
}

// Cleanup removes expired users from the flatfile.
func (db *FlatfileDB) Cleanup() error {
	lines, err := db.readAllLines()
	if err != nil {
		return err
	}

	now := time.Now().Unix()
	var newLines []string

	for _, line := range lines {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue // skip invalid line
		}

		expStr := strings.TrimSpace(parts[2])
		if expStr == "" {
			newLines = append(newLines, line)
			continue
		}

		exp, err := strconv.ParseInt(expStr, 10, 64)
		if err != nil || exp == 0 || exp > now {
			newLines = append(newLines, line)
		}
	}

	return db.writeAllLines(newLines)
}

// readAllLines reads all non-empty lines from the flatfile.
func (db *FlatfileDB) readAllLines() ([]string, error) {
	file, err := os.Open(db.path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

// writeAllLines overwrites the flatfile with the provided lines.
func (db *FlatfileDB) writeAllLines(lines []string) error {
	file, err := os.OpenFile(db.path, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, line := range lines {
		if _, err := fmt.Fprintln(file, line); err != nil {
			return err
		}
	}
	return nil
}

func (db *FlatfileDB) Close() error {
	// No persistent resources to close for flatfile
	return nil
}
