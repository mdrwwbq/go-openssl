package internal

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
	encrypt := NewOpensslEncrypt(ctx)
	if res, err := encrypt.encrypt("123456789", "aes-256-ecb", "1234567890123456", OpenSSLZeroPadding); err != nil {
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
	decrypt := NewOpensslEncrypt(ctx)
	if s, err := decrypt.decrypt(string(decodeString), "aes-256-ecb", "1234567890123456", OpenSSLRawData); err != nil {
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
	decrypt := NewOpensslEncrypt(ctx)
	if s, err := decrypt.decrypt(string(decodeString), "aes-128-ecb", "1234567890123456", OpenSSLZeroPadding); err != nil {
		panic(err)
	} else {
		fmt.Println(s)
	}
}
