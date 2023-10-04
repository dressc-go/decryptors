package base64OeapSha256

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"strings"
	"testing"
)

var key *rsa.PrivateKey
var pub *rsa.PublicKey

func init() {
	key, _ = rsa.GenerateKey(rand.Reader, 4096)
	pub = key.Public().(*rsa.PublicKey)
}

func TestEncryptDecrypt(t *testing.T) {
	text := "The quick brown fox jumps over the cipher"
	enc_text, _ := Encrypt(text, pub)
	clear_text, _ := Decrypt(enc_text, key)
	if text != clear_text {
		t.Errorf("Failed to decrypt encrypted text")
	}
}

func TestEncryptDecryptBase64Fail(t *testing.T) {
	expectErrContains := "base64 decoding failed"
	gotError := ""
	_, err := Decrypt("foobar", key)
	if err != nil {
		gotError = err.Error()
		if strings.Contains(gotError, expectErrContains) {
			return
		}
	}
	t.Errorf("Failed. Expected Error: " + expectErrContains + " got: " + gotError)
}

func TestEncryptDecryptDecryptionFail(t *testing.T) {
	expectErrContains := "decryption failed"
	gotError := ""
	_, err := Decrypt("ZmFpbCBtZQ==", key)
	if err != nil {
		gotError = err.Error()
		if strings.Contains(gotError, expectErrContains) {
			return
		}
	}
	t.Errorf("Failed. Expected Error: " + expectErrContains + " got: " + gotError)
}

func TestEncryptDecryptEncryptionFail(t *testing.T) {
	key, _ = rsa.GenerateKey(rand.Reader, 128)
	bigOne := big.NewInt(1)
	bigZero := big.NewInt(0)
	key.Primes[0] = bigOne
	key.PublicKey.N = bigZero
	key.PublicKey.E = 0
	pub = key.Public().(*rsa.PublicKey)

	expectErrContains := "encryption failed"
	gotError := ""
	text := "The quick brown fox jumps over the cipher"
	_, err := Encrypt(text, pub)
	if err != nil {
		gotError = err.Error()
		if strings.Contains(gotError, expectErrContains) {
			return
		}
	}
	t.Errorf("Failed. Expected Error: " + expectErrContains + " got: " + gotError)
}
