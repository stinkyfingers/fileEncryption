package respond

import (
	"crypto/rsa"
	"encoding/json"

	"github.com/stinkyfingers/fileEncryption/encryption"
)

// encryptContents encrypts a file (contents) using a generated cipherKey
// it then encrypts the cipherKey using the public key from the request
func EncryptContents(contents []byte, publicKeyJSON []byte) ([]byte, error) {
	// AES encrypt file
	ciphertext, cipherKey, err := encryption.AESEncrypt(contents)
	if err != nil {
		return nil, err
	}
	// RSA encrypt cipher key using public key
	var publicKey *rsa.PublicKey
	err = json.Unmarshal(publicKeyJSON, &publicKey)
	if err != nil {
		return nil, err
	}
	b, err := encryption.Encrypt(cipherKey, publicKey)
	if err != nil {
		return nil, err
	}
	m := encryption.EncodedMessage{ciphertext, b}
	j, err := json.Marshal(m)
	return j, err
}
