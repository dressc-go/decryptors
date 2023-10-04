package common

import (
	"encoding/base64"
	"github.com/dressc-go/zlogger"
	"github.com/pkg/errors"
)

func B64Decode(cipherTextB64Str string) ([]byte, error) {
	logger := zlogger.GetLogger("decryptor.B64Decode.Decrypt")
	cipherTextB64 := []byte(cipherTextB64Str)
	cipherText := make([]byte, base64.StdEncoding.DecodedLen(len(cipherTextB64)))
	n, e := base64.StdEncoding.Decode(cipherText, cipherTextB64)
	if e != nil {
		err := errors.Wrap(e, "base64 decoding failed")
		logger.Error().Err(err).Msg("")
		return nil, err
	}
	cipherText = cipherText[:n]

	return cipherText, nil
}
