package services

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

//Gen public and private key pair and write them to separate files
func GenKeys() error {

	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	privFile, err := os.Create("private_key.pem")
	if err != nil {
		return err
	}

	pemData := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	}

	err = pem.Encode(privFile, pemData)
	if err != nil {
		return err
	}

	privFile.Close()

	fmt.Println("Your key has been written to private_key.pem")

	return nil

}

func GetKeys() (*rsa.PrivateKey, error) {

	file, err := os.Open("private_key.pem")
	if err != nil {
		return nil, err
	}

	defer file.Close()

	//Create a byte slice (pemBytes) the size of the file size
	pemFileInfo, _ := file.Stat()
	var size = pemFileInfo.Size()
	pemBytes := make([]byte, size)

	//Create new reader for the file and read into pemBytes
	buffer := bufio.NewReader(file)
	_, err = buffer.Read(pemBytes)
	if err != nil {
		return nil, err
	}

	//Now decode the byte slice
	data, _ := pem.Decode(pemBytes)
	if data == nil {
		return nil, errors.New("could not read pem file")
	}

	privKeyImport, err := x509.ParsePKCS1PrivateKey(data.Bytes)
	if err != nil {
		return nil, err
	}

	return privKeyImport, nil

}

func GetPubPemFromPrivPem(privKey *rsa.PrivateKey) error {

	pubFile, err := os.Create("pub_key.pem")
	if err != nil {
		return err
	}

	pubKey := &rsa.PublicKey{
		N: privKey.N,
		E: privKey.E,
	}

	pubPemData := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(pubKey),
	}

	err = pem.Encode(pubFile, pubPemData)
	if err != nil {
		return err
	}

	fmt.Println("Have written the pub key to pub_key.pem")

	pubFile.Close()
	return nil
}
