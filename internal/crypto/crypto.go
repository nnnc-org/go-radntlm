package crypto

import (
	"crypto/des"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/md4"
	"strings"
)

func GetNTHash(password string) []byte {
	// NT hash uses UTF-16LE encoded password
	utf16le := utf16FromString(password)
	h := md4.New()
	h.Write(utf16le)
	return h.Sum(nil)
}

// utf16FromString encodes a string to UTF-16LE
func utf16FromString(s string) []byte {
	utf := make([]byte, len(s)*2)
	for i, r := range s {
		utf[i*2] = byte(r)
		utf[i*2+1] = byte(r >> 8)
	}
	return utf
}


func createDESKey(key7 []byte) []byte {
	key := make([]byte, 8)
	key[0] = key7[0] & 0xFE
	key[1] = ((key7[0]<<7 | key7[1]>>1) & 0xFE)
	key[2] = ((key7[1]<<6 | key7[2]>>2) & 0xFE)
	key[3] = ((key7[2]<<5 | key7[3]>>3) & 0xFE)
	key[4] = ((key7[3]<<4 | key7[4]>>4) & 0xFE)
	key[5] = ((key7[4]<<3 | key7[5]>>5) & 0xFE)
	key[6] = ((key7[5]<<2 | key7[6]>>6) & 0xFE)
	key[7] = ((key7[6] << 1) & 0xFE)

	// Set odd parity
	for i := range key {
		b := key[i]
		parity := byte((bitsSetCount(b) + 1) % 2)
		key[i] |= parity
	}
	return key
}

// bitsSetCount returns number of 1s in a byte
func bitsSetCount(b byte) int {
	count := 0
	for i := 0; i < 8; i++ {
		if b&(1<<i) != 0 {
			count++
		}
	}
	return count
}

// desEncrypt performs DES encryption in ECB mode
func desEncrypt(key7, challenge []byte) ([]byte, error) {
	key := createDESKey(key7)
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	encrypted := make([]byte, 8)
	block.Encrypt(encrypted, challenge)
	return encrypted, nil
}

// computeNTResponse generates NT response
func computeNTResponse(ntHash []byte, challenge []byte) (string, error) {
	// Pad NT hash to 21 bytes with zeros
	zpassword := make([]byte, 21)
	copy(zpassword, ntHash)

	var response []byte
	for i := 0; i < 21; i += 7 {
		block, err := desEncrypt(zpassword[i:i+7], challenge)
		if err != nil {
			return "", err
		}
		response = append(response, block...)
	}

	// Convert response to hex string
	return hex.EncodeToString(response), nil
}

// ValidateNTResponse checks if the provided NT response is valid
func ValidateNTResponse(ntResponseStr, challengeStr, ntHashStr string) (bool, error) {
	// Convert hex strings to bytes
	_, err := hex.DecodeString(ntResponseStr)
	if err != nil {
		return false, fmt.Errorf("invalid NT response: %v", err)
	}

	challenge, err := hex.DecodeString(challengeStr)
	if err != nil {
		return false, fmt.Errorf("invalid challenge: %v", err)
	}

	ntHash, err := hex.DecodeString(ntHashStr)
	if err != nil {
		return false, fmt.Errorf("invalid NT hash: %v", err)
	}

	// Compute the expected NT response
	expectedResponse, err := computeNTResponse(ntHash, challenge)
	if err != nil {
		return false, fmt.Errorf("error computing expected NT response: %v", err)
	}

	// Compare the computed response with the provided one
	return strings.EqualFold(expectedResponse, ntResponseStr), nil
}
