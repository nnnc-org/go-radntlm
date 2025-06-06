package backends

import (
	"os"
	"bufio"
	"fmt"
	"strings"
)

// Handle flatfiles
func FlatfileSearch(path string, username string) (string, error) {
	// Open the file
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}

	defer file.Close()

	// search file for username
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, username+":") {
			// Found the username, return the hash
			parts := strings.SplitN(line, ":", 3)

			if len(parts) < 2 {
				return "", fmt.Errorf("invalid line format: %s", line)
			}
			return strings.TrimSpace(parts[1]), nil
		}
	}

	return "", fmt.Errorf("username not found in flatfile: %s", username)

}
