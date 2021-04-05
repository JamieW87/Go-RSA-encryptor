package main

import (
	"flag"
	"fmt"
	"go-rsa-encryptor/services"
	"strings"
)

func main() {

	var action = flag.String("action", "", "Whether to decrypt or encrypt")
	flag.Parse()
	task := *action

	var err error

	switch task {
		case "gen":
			//gen the priv key and write to file
			err = services.GenKeys()
			if err != nil {
				fmt.Println("Could not generate keys:", err)
				return
			}
	case "encrypt":
		//Get key from file
		privateKey, err := services.GetKeys()
		if err != nil {
			fmt.Println("Could not retrieve key file", err)
			return
		}

		var text string
		fmt.Println("Please enter the text you would like to encrypt")
		fmt.Scan(&text)
		trimmedText := strings.TrimSuffix(text, "\n")


		cipherText, err := services.Encrypt(&privateKey.PublicKey, trimmedText)
		if err != nil {
			fmt.Println("Could not encrypt", err)
			return
		}

		fmt.Printf("Encrypted message: %x", cipherText)

	case "decrypt":
		//Get key from file
		privateKey, err := services.GetKeys()
		if err != nil {
			fmt.Println("Could not retrieve key file", err)
		}

		var text string
		fmt.Println("Please enter the encrypted text")
		fmt.Scan(&text)


		decryptedText, err := services.Decrypt(privateKey, []byte(text))
		if err != nil {
			fmt.Println("Could not decrypt text", err.Error())
			return
		}

		fmt.Println("decrypted text: ", string(decryptedText))

	default:
		fmt.Println("Please enter a valid command: 'encrypt', 'decrypt', or 'gen'.")

	}

}