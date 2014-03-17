# Simple AES Encryption library for Go

```go
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
```
