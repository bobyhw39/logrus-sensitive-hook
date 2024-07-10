package dataprocessorimpl

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

type AES struct {
	EncryptionKey []byte
}

func NewAES(encryptionKey []byte) *AES {
	return &AES{EncryptionKey: encryptionKey}
}

func (a AES) Process(data string) string {
	encryptedValue, err := encrypt(a.EncryptionKey, fmt.Sprintf("%v", data))
	if err != nil {
		return "encryption_error"
	}
	return encryptedValue
}

func encrypt(key []byte, text string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	plainText := []byte(text)
	cfb := cipher.NewCFBEncrypter(block, key[:block.BlockSize()])
	cipherText := make([]byte, len(plainText))
	cfb.XORKeyStream(cipherText, plainText)
	return base64.StdEncoding.EncodeToString(cipherText), nil
}
