package encryption

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	mathrand "math/rand"
	"os"
)

// Used to send an AES-encrypted message with an RSA-encoded key
type EncodedMessage struct {
	Message    []byte
	EncodedKey []byte
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// Generate creates a pair of keys
func Generate() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, nil, err
	}
	public := &key.PublicKey
	return key, public, nil
}

// GetPrivateKeyFromFile fetches and parses a private key from a filepath
func GetPrivateKeyFromFile(path string) (*rsa.PrivateKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	b, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("Invalid private key")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// GetPublicKeyFromFile fetches and parses a public key from a filepath
func GetPublicKeyFromFile(path string) (*rsa.PublicKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	b, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	public, err := x509.ParsePKIXPublicKey(block.Bytes)
	if publicKey, ok := public.(*rsa.PublicKey); ok {
		return publicKey, err
	}
	return nil, errors.New("No key")
}

// SavePrivateKeyToFile saves a private key to a filepath
func SavePrivateKeyToFile(path string, key *rsa.PrivateKey) error {
	data := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	return err
}

// SavePublicKeyToFile saves a public key to a file path
func SavePublicKeyToFile(path string, key *rsa.PublicKey) error {
	b, err := x509.MarshalPKIXPublicKey(key)
	data := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: b,
	})
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	return err
}

// Encrypt encrypts a message, given a public key
func Encrypt(message []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	if publicKey == nil {
		return []byte{}, errors.New("Public key is nil")
	}
	label := []byte("")
	md5hash := md5.New()
	encryptedmsg, err := rsa.EncryptOAEP(md5hash, rand.Reader, publicKey, message, label)
	return encryptedmsg, err
}

// Decrypt decrypts a message given a private key
func Decrypt(message []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	if privateKey == nil {
		return []byte{}, errors.New("Private key is nil")
	}
	label := []byte("")
	md5hash := md5.New()
	decryptedmsg, err := rsa.DecryptOAEP(md5hash, rand.Reader, privateKey, message, label)
	return decryptedmsg, err
}

// SignFile creates a rsa ignature from a hash of the file
func SignFile(f *os.File, privateKeyPath string) ([]byte, error) {
	// hash file
	b, err := ioutil.ReadFile(f.Name())
	if err != nil {
		return []byte{}, err
	}
	hashed := sha256.Sum256(b)

	// get private key
	privateKey, err := GetPrivateKeyFromFile(privateKeyPath)
	if err != nil {
		return []byte{}, errors.New("Error getting private key from path. " + err.Error())
	}
	// get signature
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	return signature, err
}

// CheckSignature confirms a file's signature with a public key
func CheckSignature(file io.Reader, signature []byte, publicKeyPath string) error {
	b, err := ioutil.ReadAll(file)
	if err != nil {
		return err
	}

	hashed := sha256.Sum256(b)

	pub, err := GetPublicKeyFromFile(publicKeyPath)
	if err != nil {
		return err
	}

	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], signature)
}

//AES

// AESEncrypt encrypts a message, returning the encrypted message and the cipherKey used
// NOTE: the cipherKey is not encoded on return
func AESEncrypt(plaintext []byte) ([]byte, []byte, error) {
	cipherKey := randBytes(24)
	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return nil, nil, err
	}
	h := hex.EncodeToString(plaintext)
	ciphertext := make([]byte, aes.BlockSize+len(h))
	iv := ciphertext[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(h))
	return ciphertext, cipherKey, nil
}

// AESDecrypt decrypts a message with a given cipherKey
func AESDecrypt(ciphertext, cipherKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return []byte{}, err
	}
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("Ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(ciphertext, ciphertext)
	plaintext, err := hex.DecodeString(string(ciphertext))
	return plaintext, err
}

// randBytes creates a random []byte of len length
func randBytes(length int) []byte {
	b := make([]byte, length)
	for i := range b {
		b[i] = letterBytes[mathrand.Intn(len(letterBytes))]
	}
	return b
}
