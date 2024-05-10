package example

import (
	"context"
	"encoding/base64"
	"github.com/mdrwwbq/go-openssl/src"
	"testing"
)

var (
	ctx context.Context
	key = "1234567890123456"
	iv  = ""
)

func TestAesEcbEncryptNormal(t *testing.T) {
	type args struct {
		data    string
		method  string
		options int
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{name: "AES-128-ECB options=0", args: args{data: "222", method: "aes-128-ecb", options: src.OpenSSLNormalData}, want: "Q0vftwpmFHJfzUQbjV18DQ=="},
		{name: "AES-192-ECB options=0", args: args{data: "222", method: "aes-192-ecb", options: src.OpenSSLNormalData}, want: "3oT4CAAYlULx/rA6I2CR9A=="},
		{name: "AES-256-ECB options=0", args: args{data: "222", method: "aes-256-ecb", options: src.OpenSSLNormalData}, want: "/cDWbMQMnTPhvlcLwf/TBQ=="},
	}
	encrypt := src.NewOpensslEncrypt(ctx)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := encrypt.Encrypt(tt.args.data, tt.args.method, key, tt.args.options, iv); got != tt.want || err != nil {
				if err != nil {
					t.Errorf("Encrypt() error = %v", err)
				} else {
					t.Errorf("Encrypt() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
func TestAesEcbEncryptRawData(t *testing.T) {
	type args struct {
		data    string
		method  string
		options int
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{name: "AES-128-ECB options=1", args: args{data: "222", method: "aes-128-ecb", options: src.OpenSSLRawData}, want: "Q0vftwpmFHJfzUQbjV18DQ=="},
		{name: "AES-192-ECB options=1", args: args{data: "222", method: "aes-192-ecb", options: src.OpenSSLRawData}, want: "3oT4CAAYlULx/rA6I2CR9A=="},
		{name: "AES-256-ECB options=1", args: args{data: "222", method: "aes-256-ecb", options: src.OpenSSLRawData}, want: "/cDWbMQMnTPhvlcLwf/TBQ=="},
	}
	encrypt := src.NewOpensslEncrypt(ctx)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := encrypt.Encrypt(tt.args.data, tt.args.method, key, tt.args.options, iv); err != nil {
				t.Errorf("Encrypt() error = %v", err)
			} else {
				got = base64.StdEncoding.EncodeToString([]byte(got))
				if got != tt.want {
					t.Errorf("Encrypt() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
