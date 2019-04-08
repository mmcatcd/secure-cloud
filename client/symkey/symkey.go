package symkey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// EncryptData encrypts data using a symmetric key.
func EncryptData(data, key []byte) ([]byte, error) {
	// Creates cipher and Galois/Counter mode object for sym key crypto block ciphers.
	gcm, err := genGCM(key)
	if err != nil {
		return nil, err
	}

	// Create a random nonce.
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	// Encrypt using Seal.
	return gcm.Seal(nonce, nonce, data, nil), nil
}

// DecryptData decrypts data using a symmetric key.
func DecryptData(encryptedData, key []byte) ([]byte, error) {
	// Creates cipher and Galois/Counter mode object for sym key crypto block ciphers.
	gcm, err := genGCM(key)
	if err != nil {
		return nil, err
	}

	if len(encryptedData) < gcm.NonceSize() {
		return nil, err
	}

	nonce, encryptedData := encryptedData[:gcm.NonceSize()], encryptedData[gcm.NonceSize():]
	data, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func genGCM(key []byte) (cipher.AEAD, error) {
	// Generate AES cipher from the key.
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Use Galois mode for sym key crypto block ciphers.
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	return gcm, nil
}

// GenerateKey generates a random 32-byte sequence to use as a symmetric key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)

	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	return key, nil
}
