# Simple AES Encryption library for Go


```go
import aes "github.com/c9s/go-aes-crypt"
func main() {
    key := []byte("example key 1234")
    cryptor := aes.NewAESCrypt(key, 16)
    msg := cryptor.EncryptStringToBase64String("plain text")
    fmt.Println(msg)
    decrypted, err := cryptor.DecryptBase64StringToString(msg)
    if err != nil {
        panic(err)
    }
    fmt.Println(decrypted)
}
```

## Install

    go get -x github.com/c9s/go-aes-crypt
