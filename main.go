package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"os"

	"github.com/youmark/pkcs8"
)

type (
	Person struct {
		Firstname string                 `json:"firstname" bson:"firstname"`
		Lastname  string                 `json:"lastname" bson:"lastname"`
		Favorite  map[string]interface{} `json:"favorite" bson:"favorite"`
	}
)

func main() {

	//Get key from file
	privateKey, err := GetKeys()
	if err != nil {
		fmt.Println("Could not retrieve key file", err)
		return
	}

	m1 := generateMockData(privateKey)
	byt, _ := json.Marshal(m1)

	// len
	// encrypt
	hash := sha256.New()
	encryptedBytes, err := EncryptOAEP(hash, &privateKey.PublicKey, byt)
	if err != nil {
		fmt.Println("Could encrypt OAEP", err)
		return
	}
	fmt.Printf("Encrypted message: %x \n", encryptedBytes)

	//len
	// decrypt
	decryptedText, _ := DecryptOAEP(hash, privateKey, encryptedBytes)
	fmt.Println("Decrypted text: ", string(decryptedText))

	// font end decrpyt example
	/*
		encrypted := "g1aa4AdtBCu6yKxiJ98SO2FXPVhIGOjFYorysWHvB47RexIrkoyz8Vy+Vc5zUY6EauXyrWD8PvIp+kQ4AZlA9CT9ta0EFTsVziz8Jym4NhPIBacqzrahB2KNtioSPJVXD8tu9fKeXZchdZNJNxNl2J7OLfxrRtaT/NArg5chk3NfpAT+bgCofDvcAtunibtWAqo/aExOQnUcqigC9KTAAkj7iEfR5rOsxcHFtm0N7pY21B9VK5d81DmvWmdadK5H0ioJ190Se8uC1QcF3DjKYVK/OSSM8VimGK/EXB54Hd3ek6nJSuVpa6tGdJonksDicevWj94Uy/9RUVC0+qAzug=="
		cipherText, err := base64.StdEncoding.DecodeString(encrypted)
		if err != nil {
			log.Fatal("cannot en key", err)
		}

		originText, err := RSADecrypt(privateKey, []byte(cipherText))
		if err != nil {
			log.Fatal("cannot de key", err)
		}

		println("originText: ", string(originText))
	*/
}

func RSADecrypt(privateKey *rsa.PrivateKey, cipherText []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherText)
}

func DecryptOAEP(hash hash.Hash, privateKey *rsa.PrivateKey, msg []byte) ([]byte, error) {
	msgLen := len(msg)
	step := privateKey.PublicKey.Size()
	var decryptedBytes []byte
	for start := 0; start < msgLen; start += step {
		finish := start + step
		if finish > msgLen {
			finish = msgLen
		}

		decryptedText, err := Decrypt(privateKey, msg[start:finish])
		if err != nil {
			return nil, err
		}

		decryptedBytes = append(decryptedBytes, decryptedText...)
	}

	return decryptedBytes, nil
}

func EncryptOAEP(hash hash.Hash, public *rsa.PublicKey, msg []byte) ([]byte, error) {
	// len
	msgLen := len(msg)
	step := public.Size() - 2*hash.Size() - 2
	var encryptedBytes []byte

	for start := 0; start < msgLen; start += step {
		finish := start + step
		if finish > msgLen {
			finish = msgLen
		}
		// encrypt
		cipherText, err := Encrypt(public, msg[start:finish])
		if err != nil {
			fmt.Println("Could not encrypt", err)
			return []byte{}, err
		}

		encryptedBytes = append(encryptedBytes, cipherText...)
	}
	return encryptedBytes, nil
}

// GetKeys
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

	// with pass
	decryptedPrivateKey, err := pkcs8.ParsePKCS8PrivateKey(data.Bytes, []byte("your pass phrase"))
	if err != nil {
		return nil, errors.New("could not read pem with passphase")

	}

	return decryptedPrivateKey.(*rsa.PrivateKey), nil

}

func Encrypt(pub *rsa.PublicKey, b []byte) ([]byte, error) {
	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		pub,
		b,
		nil)
	if err != nil {
		return nil, err
	}

	return encryptedBytes, nil
}

func Decrypt(privKey *rsa.PrivateKey, cipherText []byte) ([]byte, error) {

	decryptedBytes, err := rsa.DecryptOAEP(sha256.New(), nil, privKey, cipherText, nil)
	if err != nil {
		return nil, err
	}

	return decryptedBytes, nil
}

func generateMockData(privateKey *rsa.PrivateKey) *Person {

	favorite := map[string]interface{}{
		"music": "KDA",
		"game":  "dead by daylight",
	}
	m1 := &Person{
		Firstname: "Jirawan",
		Lastname:  "Chuapradit",
		Favorite:  favorite,
	}

	return m1
}
