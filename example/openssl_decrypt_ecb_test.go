package example

import (
	"encoding/base64"
	"github.com/mdrwwbq/openssl"
	"testing"
)

func TestAesEcbDecrypt(t *testing.T) {
	type args struct {
		data    string
		method  string
		options int
		key     string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"key appends null", args{"ESxnVJjbMJhD2I6MW4KtAg==", "aes-128-ecb", openssl.RawData, "123"}, "222"},
		{"aes-128-ecb option is normal", args{"Q0vftwpmFHJfzUQbjV18DQ==", "aes-128-ecb", openssl.NormalData, key}, "222"},
		{"aes-192-ecb option is normal", args{"3oT4CAAYlULx/rA6I2CR9A==", "aes-192-ecb", openssl.NormalData, key}, "222"},
		{"aes-256-ecb option is normal", args{"/cDWbMQMnTPhvlcLwf/TBQ==", "aes-256-ecb", openssl.NormalData, key}, "222"},
		{"aes-128-ecb option is PKCS7", args{"Q0vftwpmFHJfzUQbjV18DQ==", "aes-128-ecb", openssl.RawData | openssl.NoPadding, key}, "222"},
		{"aes-192-ecb option is PKCS7", args{"3oT4CAAYlULx/rA6I2CR9A==", "aes-192-ecb", openssl.RawData | openssl.NoPadding, key}, "222"},
		{"aes-256-ecb option is PKCS7", args{"/cDWbMQMnTPhvlcLwf/TBQ==", "aes-256-ecb", openssl.RawData | openssl.NoPadding, key}, "222"},
		{"aes-128-ecb option is raw data", args{"Q0vftwpmFHJfzUQbjV18DQ==", "aes-128-ecb", openssl.RawData, key}, "222"},
		{"aes-192-ecb option is raw data", args{"3oT4CAAYlULx/rA6I2CR9A==", "aes-192-ecb", openssl.RawData, key}, "222"},
		{"aes-256-ecb option is raw data", args{"/cDWbMQMnTPhvlcLwf/TBQ==", "aes-256-ecb", openssl.RawData, key}, "222"},
		{"aes-128-ecb option is zero padding", args{"/NCcLXFd+v8a3SwFF79/WA==", "aes-128-ecb", openssl.ZeroPadding, key}, "222"},
		{"aes-192-ecb option is zero padding", args{"uCf166kiJbyGd/iNaPI0mA==", "aes-192-ecb", openssl.ZeroPadding, key}, "222"},
		{"aes-256-ecb option is zero padding", args{"pMNT3lHKy8FvSOwhPOO/Sg==", "aes-256-ecb", openssl.ZeroPadding, key}, "222"},
	}
	decrypt := openssl.NewOpenssl(ctx)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newData, err := base64.StdEncoding.DecodeString(tt.args.data)
			if err != nil {
				t.Errorf("Decrypt() error = %v", err)
			}
			if got, err := decrypt.Decrypt(string(newData), tt.args.method, tt.args.key, tt.args.options, iv); got != tt.want || err != nil {
				if err != nil {
					t.Errorf("Encrypt() error = %v", err)
				} else {
					t.Errorf("Encrypt() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
