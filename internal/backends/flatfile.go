package backends

import (
	"os"
	"bufio"
	"fmt"
	"strings"
	"strconv"
)

// Handle flatfiles
func FlatfileSearch(path string, username string) (string, int64, error) {
	// Open the file
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}

	defer file.Close()

	// search file for username
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, username+":") {
			// Found the username, return the hash
			parts := strings.SplitN(line, ":", 3)

			if len(parts) < 3 {
				return "", 0, fmt.Errorf("invalid line format for user '%s'", username)
			}

			// get expiration date
			// If the expiration date is not set, return 0
			expiration := int64(0)
			if len(parts) == 3 {
				expirationStr := strings.TrimSpace(parts[2])
				if expirationStr != "" {
					expiration, err = strconv.ParseInt(expirationStr, 10, 64)
					if err != nil {
						return "", 0, fmt.Errorf("expiration date '%s' invalid", expirationStr)
					}
				}
			}

			return strings.TrimSpace(parts[1]), expiration, nil
		}
	}

	return "", 0, nil

}
