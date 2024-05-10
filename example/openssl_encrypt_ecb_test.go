package example

import (
	"context"
	"encoding/base64"
	"github.com/mdrwwbq/openssl"
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
		{name: "AES-128-ECB options=0", args: args{data: "222", method: "aes-128-ecb", options: openssl.NormalData}, want: "Q0vftwpmFHJfzUQbjV18DQ=="},
		{name: "AES-192-ECB options=0", args: args{data: "222", method: "aes-192-ecb", options: openssl.NormalData}, want: "3oT4CAAYlULx/rA6I2CR9A=="},
		{name: "AES-256-ECB options=0", args: args{data: "222", method: "aes-256-ecb", options: openssl.NormalData}, want: "/cDWbMQMnTPhvlcLwf/TBQ=="},
		{name: "AES-128-ECB options=0 key length appends null", args: args{data: "222", method: "aes-128-ecb", options: openssl.NormalData}, want: "ESxnVJjbMJhD2I6MW4KtAg=="},
	}
	encrypt := openssl.NewOpenssl(ctx)
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
		{name: "AES-128-ECB options=1", args: args{data: "222", method: "aes-128-ecb", options: openssl.RawData}, want: "Q0vftwpmFHJfzUQbjV18DQ=="},
		{name: "AES-192-ECB options=1", args: args{data: "222", method: "aes-192-ecb", options: openssl.RawData}, want: "3oT4CAAYlULx/rA6I2CR9A=="},
		{name: "AES-256-ECB options=1", args: args{data: "222", method: "aes-256-ecb", options: openssl.RawData}, want: "/cDWbMQMnTPhvlcLwf/TBQ=="},
	}
	encrypt := openssl.NewOpenssl(ctx)
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

// TestAesEcbEncryptZeroPadding
func TestAesEcbEncryptZeroPadding(t *testing.T) {
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
		{name: "AES-128-ECB options=2", args: args{data: "222", method: "aes-128-ecb", options: openssl.ZeroPadding}, want: "/NCcLXFd+v8a3SwFF79/WA=="},
		{name: "AES-192-ECB options=2", args: args{data: "222", method: "aes-192-ecb", options: openssl.ZeroPadding}, want: "uCf166kiJbyGd/iNaPI0mA=="},
		{name: "AES-256-ECB options=2", args: args{data: "222", method: "aes-256-ecb", options: openssl.ZeroPadding}, want: "pMNT3lHKy8FvSOwhPOO/Sg=="},
		{name: "AES-128-ECB options=3", args: args{data: "222", method: "aes-128-ecb", options: openssl.NoPadding}, want: "Q0vftwpmFHJfzUQbjV18DQ=="},
		{name: "AES-192-ECB options=3", args: args{data: "222", method: "aes-192-ecb", options: openssl.NoPadding}, want: "3oT4CAAYlULx/rA6I2CR9A=="},
		{name: "AES-256-ECB options=3", args: args{data: "222", method: "aes-256-ecb", options: openssl.NoPadding}, want: "/cDWbMQMnTPhvlcLwf/TBQ=="},
	}
	encrypt := openssl.NewOpenssl(ctx)
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
func TestAesEcbEncryptKeyAppendNull(t *testing.T) {
	encrypt := openssl.NewOpenssl(ctx)
	want := `ESxnVJjbMJhD2I6MW4KtAg==`
	if got, err := encrypt.Encrypt("222", "aes-128-ecb", "123", openssl.NormalData, iv); err != nil {
		t.Errorf("Encrypt() error = %v", err)
	} else {
		if got != want {
			t.Errorf("Encrypt() = %v, want %v", got, want)
		}
	}
}
