package aescrypt

import "testing"

func TestAes(t *testing.T) {

	key := []byte("example key 1234")
	cryptor := NewAESCrypt(key, 16)
	msg := cryptor.EncryptStringToBase64String("plain text")
	t.Log(msg)
	decrypted, err := cryptor.DecryptBase64StringToString(msg)
	if err != nil {
		panic(err)
	}

	t.Log("Length:", len(decrypted))

	if len(decrypted) != len("plain text") {
		t.Fatal("Unmatched decrypted text length")
	}

	if decrypted != "plain text" {
		t.Fatal("Unmatched decrypted text")
	}

}
