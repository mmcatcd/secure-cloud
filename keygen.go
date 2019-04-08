package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) == 2 {
		GeneratePair(os.Args[1])
	} else {
		fmt.Println("Usage: keygen <keyname>")
	}
}

func GeneratePair(keyName string) {
	if checkRSA(keyName) {
		fmt.Println("Generating a public/private key pair...")
		generateAsymmetricPair(keyName)
		fmt.Println("Generated RSA key pair!")
	} else {
		fmt.Println("RSA key pair already generated!")
	}
}

func generateAsymmetricPair(keyName string) {
	os.Mkdir("keys", os.ModePerm)

	reader := rand.Reader
	bitSize := 2048

	// Generate asymmetric key.
	key, err := rsa.GenerateKey(reader, bitSize)
	checkError(err)

	// Saves keys as .pem files.
	savePEMKey(keyName+".pem", key)
	savePublicPEMKey(keyName+"-public.pem", key.PublicKey)
}

func checkRSA(keyName string) bool {
	_, err := os.Stat(keyName)
	return os.IsNotExist(err)
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
