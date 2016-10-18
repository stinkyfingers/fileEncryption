package request

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"io"
	"os"

	"github.com/stinkyfingers/fileEncryption/encryption"
)

var tempFile = "tempfile.txt"

// CreateRequest creates a key pair and marshalls the public for http transmission
func CreateRequest() ([]byte, *rsa.PrivateKey, error) {
	privateKey, publicKey, err := encryption.Generate()
	if err != nil {
		return nil, nil, err
	}
	j, err := json.Marshal(publicKey)
	return j, privateKey, err
}

// HandleResponse decrypts the cipherKey with the private key
// and decrypts the message with the cipherKey
func HandleResponse(b []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	var m encryption.EncodedMessage
	err := json.Unmarshal(b, &m)
	if err != nil {
		return nil, err
	}
	// decrypt symmetrical key with private key
	cipherKey, err := encryption.Decrypt(m.EncodedKey, privateKey)
	if err != nil {
		return nil, err
	}
	// decrypt content with symmetrical key
	return encryption.AESDecrypt(m.Message, cipherKey)
}

// WriteToFile writes bytes to file
func WriteToFile(b []byte, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, bytes.NewBuffer(b))
	return err
}
