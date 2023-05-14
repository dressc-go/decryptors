package base64OeapSha1

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"github.com/dressc-go/zlogger"
	"github.com/pkg/errors"
)

func Decrypt(cipherTextB64Str string, key *rsa.PrivateKey) (string, error) {
	logger := zlogger.GetLogger("decryptor.base64OeapSha1.Decrypt")
	cipherTextB64 := []byte(cipherTextB64Str)
	cipherText := make([]byte, base64.StdEncoding.DecodedLen(len(cipherTextB64)))
	n, e := base64.StdEncoding.Decode(cipherText, cipherTextB64)
	if e != nil {
		err := errors.Wrap(e, "base64 decoding failed")
		logger.Error().Err(err).Msg("")
		return "", err
	}
	cipherText = cipherText[:n]
	clearText, e := rsa.DecryptOAEP(sha1.New(), nil, key, cipherText, []byte(""))
	if e != nil {
		err := errors.Wrap(e, "decryption failed")
		logger.Error().Err(err).Msg("")
		return "", err
	}
	ctx := string(clearText)
	return ctx, nil
}

func Encrypt(clearText string, key *rsa.PublicKey) (string, error) {
	logger := zlogger.GetLogger("decryptor.base64OeapSha1.EnCrypt")
	decClearText := []byte(clearText)
	cipherText, e := rsa.EncryptOAEP(sha1.New(), rand.Reader, key, decClearText, []byte(""))
	if e != nil {
		err := errors.Wrap(e, "encryption failed")
		logger.Error().Err(err).Msg("")
		return "", err
	}
	cipherTextB64 := base64.StdEncoding.EncodeToString(cipherText)
	return cipherTextB64, nil
}
