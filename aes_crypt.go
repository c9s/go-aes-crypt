package aescrypt

/*


Usage:

	func main() {
		key := []byte("example key 1234")
		cryptor := NewAESCrypt(key, 16)
		msg := cryptor.EncryptStringToBase64String("plain text")
		fmt.Println(msg)
		decrypted, err := cryptor.DecryptBase64StringToString(msg)
		if err != nil {
			panic(err)
		}
		fmt.Println(decrypted)
	}

*/

import (
	"bytes"
	"code.google.com/p/go.crypto/pbkdf2"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"io"
)

type AESCrypt struct {
	Key    []byte
	IVSize int // bytes
}

func NewAESCrypt(key []byte, size int) *AESCrypt {
	return &AESCrypt{Key: key, IVSize: size}
}

func (self *AESCrypt) Encrypt(plaintext []byte) []byte {
	return Encrypt(plaintext, self.Key)
}

/*
Encrypt bytes to base64 string
*/
func (self *AESCrypt) EncryptToBase64String(plaintext []byte) string {
	return base64.StdEncoding.EncodeToString(Encrypt(plaintext, self.Key))
}

/**
Decrypt base64string to bytes
*/
func (self *AESCrypt) DecryptBase64String(base64string string) ([]byte, error) {
	msg, err := base64.StdEncoding.DecodeString(base64string)
	if err != nil {
		return []byte{}, err
	}

	decrypted, err := Decrypt(msg, self.Key)
	if err != nil {
		return []byte{}, err
	}
	return decrypted, nil
}

/*
Encrypt bytes to base64 string
*/
func (self *AESCrypt) EncryptStringToBase64String(plaintext string) string {
	return base64.StdEncoding.EncodeToString(Encrypt([]byte(plaintext), self.Key))
}

/**
Decrypt base64string to bytes
*/
func (self *AESCrypt) DecryptBase64StringToString(base64string string) (string, error) {
	msg, err := base64.StdEncoding.DecodeString(base64string)
	if err != nil {
		return "", err
	}
	decrypted, err := Decrypt(msg, self.Key)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

func (self *AESCrypt) Decrypt(message []byte) ([]byte, error) {
	b, err := Decrypt(message, self.Key)
	if err != nil {
		return []byte{}, err
	}
	return b, nil
}

func Encrypt(plaintext []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	//

	// {IV} + {plaintext len}
	// ciphertext := make([]byte, aes.BlockSize+len(plaintext)+10)
	ciphertext := make([]byte, len(plaintext))

	// create iv from random stream
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, plaintext)

	result := append(iv, ciphertext...)
	hmac := pbkdf2.Key([]byte(result), key, 1000, 16, sha1.New)
	result = append(result, hmac...)
	return result
}

func Decrypt(message []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	// The first 16 bytes are IV
	iv := message[0:16]
	em := message[16 : len(message)-16]
	hmac := message[len(message)-16:]

	hmac2 := pbkdf2.Key(message[:len(message)-16], key, 1000, 16, sha1.New)

	if bytes.Compare(hmac, hmac2) != 0 {
		return []byte{}, errors.New("Unmatched hmac")
	}
	plaintext := make([]byte, len(em))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, em)
	return plaintext, nil
}
