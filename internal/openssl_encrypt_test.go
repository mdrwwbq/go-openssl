package internal

import (
	"context"
	"fmt"
	"testing"
)

var (
	ctx = context.Background()
)

func TestAes128EcbEncrypt(t *testing.T) {

	encrypt := NewOpensslEncrypt(ctx)
	if res, err := encrypt.encrypt("12345678901234", "aes-128-ecb", "123456789012345", OpenSSLZeroPadding); err != nil {
		panic(err)
	} else {
		fmt.Println(res)
	}

}
