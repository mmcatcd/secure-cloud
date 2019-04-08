package asymkey

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"
)

// GetKeysFromFile parses .pem private into public and private rsa key from key path.
func GetKeysFromFile(filename string) (*rsa.PublicKey, *rsa.PrivateKey, error) {
	// Check that key in path exists
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return nil, nil, err
	}

	fmt.Println("Opening file!")

	privateKeyFile, err := os.Open(filename)
	if err != nil {
		return nil, nil, err
	}

	pemfileinfo, _ := privateKeyFile.Stat()
	size := pemfileinfo.Size()
	pembytes := make([]byte, size)

	buffer := bufio.NewReader(privateKeyFile)
	_, err = buffer.Read(pembytes)

	data, _ := pem.Decode([]byte(pembytes))

	privateKeyFile.Close()

	privateKey, err := x509.ParsePKCS1PrivateKey(data.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return &privateKey.PublicKey, privateKey, nil
}

// GetPublicKeyFromFile takes public key .pem file and generates parses it to an rsa public key.
func GetPublicKeyFromFile(filename string) (*rsa.PublicKey, error) {
	// Check that key in path exists
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return nil, err
	}

	fmt.Println("Reading public key file...")

	publicKeyFile, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	pemfileinfo, _ := publicKeyFile.Stat()
	size := pemfileinfo.Size()
	pembytes := make([]byte, size)

	buffer := bufio.NewReader(publicKeyFile)
	_, err = buffer.Read(pembytes)

	data, _ := pem.Decode([]byte(pembytes))

	publicKeyFile.Close()

	publicKey, err := x509.ParsePKCS1PublicKey(data.Bytes)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

// EncryptFromPath encrypts data from private key .pem file path.
func EncryptFromPath(data []byte, keypath string) ([]byte, error) {
	publicKey, _, err := GetKeysFromFile(keypath)
	if err != nil {
		return nil, err
	}

	encryptedData, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, data, nil)
	if err != nil {
		return nil, err
	}

	return encryptedData, nil
}

// Encrypt encrypts data from rsa public key.
func Encrypt(data []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	encryptedData, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, data, nil)
	if err != nil {
		return nil, err
	}

	return encryptedData, nil
}

// DecryptFromPath decrypts data from private key .pem file path.
func DecryptFromPath(encryptedData []byte, keypath string) ([]byte, error) {
	_, privateKey, err := GetKeysFromFile(keypath)
	if err != nil {
		return nil, err
	}

	data, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedData, nil)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// Decrypt decrypts data from rsa private key.
func Decrypt(encryptedData []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	data, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedData, nil)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func savePEMKey(fileName string, key *rsa.PrivateKey) {
	outFile, err := os.Create(fileName)
	checkError(err)
	defer outFile.Close()

	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	err = pem.Encode(outFile, privateKey)
	checkError(err)
}

func savePublicPEMKey(fileName string, pubkey rsa.PublicKey) {
	asn1Bytes, err := asn1.Marshal(pubkey)
	checkError(err)

	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	pemfile, err := os.Create(fileName)
	checkError(err)
	defer pemfile.Close()

	err = pem.Encode(pemfile, pemkey)
	checkError(err)
}

func checkError(err error) {
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		os.Exit(1)
	}
}
