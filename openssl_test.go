package openssl

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"
)

var (
	ctx = context.Background()
)

func TestAes128EcbEncrypt(t *testing.T) {
	encrypt := NewOpenssl(ctx)
	if res, err := encrypt.Encrypt("123456789", "aes-256-ecb", "1234567890123456", ZeroPadding); err != nil {
		panic(err)
	} else {
		fmt.Println(res)
		fmt.Println(base64.StdEncoding.EncodeToString([]byte(res)))
	}

}
func TestAes128EcbDecrypt(t *testing.T) {
	encryptString := `kjV0ZtJJI1TY7qv2JAGCbSns+rOONAZyJVf/7ONufWw=`
	decodeString, err := base64.StdEncoding.DecodeString(encryptString)
	if err != nil {
		panic(err)
	}
	decrypt := NewOpenssl(ctx)
	if s, err := decrypt.Decrypt(string(decodeString), "aes-256-ecb", "1234567890123456", RawData); err != nil {
		panic(err)
	} else {
		fmt.Println(s)
	}

}
func TestAes128EcbDecryptZeroPadding(t *testing.T) {
	encryptString := `eAekYpuAYmn4efcW+GpDPw==`
	decodeString, err := base64.StdEncoding.DecodeString(encryptString)
	if err != nil {
		panic(err)
	}
	decrypt := NewOpenssl(ctx)
	if s, err := decrypt.Decrypt(string(decodeString), "aes-128-ecb", "1234567890123456", ZeroPadding); err != nil {
		panic(err)
	} else {
		fmt.Println(s)
	}
}

func TestAes128CbcEncrypt(t *testing.T) {
	encrypt := NewOpenssl(ctx)
	iv := "0123456789abcdef"
	if s, err := encrypt.Encrypt("aa", "aes-128-cbc", "0123456789abcdef", RawData, iv); err != nil {
		panic(err)
	} else {
		fmt.Println(s)
	}
}

func TestAes128CbcDecrypt(t *testing.T) {
	decrypt := NewOpenssl(ctx)
	iv := "0123456789abcdef"
	newData, err := base64.StdEncoding.DecodeString(`ERw0bfKnJvwP5jQu+YWxkw==`)
	if err != nil {
		panic(err)
	}
	if s, err := decrypt.Decrypt(string(newData), "aes-128-cbc", "0123456789abcdef", RawData, iv); err != nil {
		panic(err)
	} else {
		fmt.Println(s)
	}
}
