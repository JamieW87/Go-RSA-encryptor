package services

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
)

func Encrypt(pub *rsa.PublicKey, text string) ([]byte, error) {

	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		pub,
		[]byte(text),
		nil)
	if err != nil {
		return nil, err
	}

	return encryptedBytes, nil
}

func Decrypt(privKey *rsa.PrivateKey, cipherText []byte) ([]byte, error) {

	textHexDec, _ := hex.DecodeString(string(cipherText))

	decryptedBytes, err := rsa.DecryptOAEP(sha256.New(), nil, privKey, textHexDec, nil)
	if err != nil {
		return nil, err
	}

	return decryptedBytes, nil
}

