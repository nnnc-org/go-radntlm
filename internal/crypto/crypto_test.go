package crypto

import (
	"encoding/hex"
	"strings"
	"testing"
)

/* Good known tests
 *
 * Password | NT Hash                           | Session Key
 * ---------|-----------------------------------|------------------------------
 * Password | a4f49c406510bdcab6824ee7c30fd852 | D87262B0CDE4B1CB7499BECCCDF10784
 * password | 8846f7eaee8fb117ad06bdd830b7586c | 5EB63BBBE01EEED093CB22BB8F5ACDC3
 * test     | 0cbc6611f5540bd0809a388dc95a615b | D67C5A2D8E6F3C4D9E8B7A6C5D4E3F2A1
 *
 */

func TestUtf16FromString(t *testing.T) {
	s := "Test"
	expected := []byte{0x54, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00}
	got := utf16FromString(s)
	if !equalBytes(got, expected) {
		t.Errorf("utf16FromString(%q) = %v, want %v", s, got, expected)
	}
}

func TestGetNTHash(t *testing.T) {
	password := "Password"
	expected, _ := hex.DecodeString("a4f49c406510bdcab6824ee7c30fd852")
	got := GetNTHash(password)
	if !equalBytes(got, expected) {
		t.Errorf("GetNTHash(%q) = %x, want %x", password, got, expected)
	}
}

func TestCreateNTSessionKey(t *testing.T) {
	// NT hash for "Password" is a4f49c406510bdcab6824ee7c30fd852
	// Session key is MD4(NT hash) = D87262B0CDE4B1CB7499BECCCDF10784
	nthash := "a4f49c406510bdcab6824ee7c30fd852"
	expected := "D87262B0CDE4B1CB7499BECCCDF10784"
	got := CreateNTSessionKey(nthash)
	if !strings.EqualFold(got, expected) {
		t.Errorf("CreateNTSessionKey(%q) = %s, want %s", nthash, got, expected)
	}
}

func TestBitsSetCount(t *testing.T) {
	if bitsSetCount(0xFF) != 8 {
		t.Error("bitsSetCount(0xFF) should be 8")
	}
	if bitsSetCount(0x00) != 0 {
		t.Error("bitsSetCount(0x00) should be 0")
	}
	if bitsSetCount(0xF0) != 4 {
		t.Error("bitsSetCount(0xF0) should be 4")
	}
}

func TestCreateDESKeyLength(t *testing.T) {
	key7 := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD}
	key := createDESKey(key7)
	if len(key) != 8 {
		t.Errorf("createDESKey length = %d, want 8", len(key))
	}
}

func TestDesEncryptAndComputeNTResponse(t *testing.T) {
	ntHash, _ := hex.DecodeString("8846f7eaee8fb117ad06bdd830b7586c")
	challenge, _ := hex.DecodeString("0123456789abcdef")
	resp, err := computeNTResponse(ntHash, challenge)
	if err != nil {
		t.Fatalf("computeNTResponse error: %v", err)
	}
	if len(resp) != 48 { // 24 bytes hex-encoded
		t.Errorf("computeNTResponse length = %d, want 48", len(resp))
	}
	validResponse := "dd5428b01e86f4dfcabeac394946dbd43ee88f794dd63255"
	if resp != validResponse {
		t.Errorf("computeNTResponse = %s, want %s", resp, validResponse)
	}
}

func TestValidateNTResponse(t *testing.T) {
	ntHash := "8846f7eaee8fb117ad06bdd830b7586c"
	challenge := "0123456789abcdef"
	ntResp := "dd5428b01e86f4dfcabeac394946dbd43ee88f794dd63255"
	valid, err := ValidateNTResponse(ntResp, challenge, ntHash)
	if err != nil {
		t.Fatalf("ValidateNTResponse error: %v", err)
	}
	if !valid {
		t.Error("ValidateNTResponse should return true for correct response")
	}

	invalid, err := ValidateNTResponse("badntresponse", challenge, ntHash)
	if err == nil && invalid {
		t.Error("ValidateNTResponse should return false for incorrect response")
	}
}

// Helper functions
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
