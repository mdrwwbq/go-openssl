package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
)

type Openssl struct {
	ctx context.Context
}

func NewOpenssl(ctx context.Context) *Openssl {
	return &Openssl{ctx: ctx}
}

// Encrypt 加密
func (s *Openssl) Encrypt(data, method, key string, options int, iv ...string) (res string, err error) {
	res = ""
	if !CheckCipherMethodIsExist(method) {
		return "", errors.New("cipher method is not exist")
	}
	newKey := s.getKey(method, key)
	blockCipher, err := aes.NewCipher([]byte(newKey))
	if err != nil {
		return "", err
	}
	newData := []byte(data)

	switch options {
	case OpenSSLRawData:
		newData = s.PKCS7Padding(newData, blockCipher.BlockSize())
	case OpenSSLZeroPadding:
		newData = s.PKCSZeroPadding(newData, blockCipher.BlockSize())
	case OpenSSLNormalData, OpenSSLNoPadding:
		newData = s.PKCS7Padding(newData, blockCipher.BlockSize())
	}
	dst := make([]byte, len(newData))
	switch method {
	case OpenSSLCipherMethodAes128Ecb, OpenSSLCipherMethodAes192Ecb, OpenSSLCipherMethodAes256Ecb:
		// ECB
		encrypter := newECBEncrypter(blockCipher)
		encrypter.CryptBlocks(dst, newData)
	case OpenSSLCipherMethodAes128Cbc, OpenSSLCipherMethodAes192Cbc, OpenSSLCipherMethodAes256Cbc:
		// CBC
	}
	switch options {
	case OpenSSLRawData, OpenSSLNoPadding, OpenSSLZeroPadding:
		res = string(dst)
	default:
		res = base64.StdEncoding.EncodeToString(dst)
	}
	return res, nil
}

// Decrypt 解密
func (s *Openssl) Decrypt(data, method, key string, options int, iv ...string) (res string, err error) {
	if data == "" {
		return "", nil
	}
	res = ""
	if !CheckCipherMethodIsExist(method) {
		return "", errors.New("cipher method is not exist")
	}
	newKey := s.getKey(method, key)
	blockCipher, err := aes.NewCipher([]byte(newKey))
	if err != nil {
		return "", err
	}
	newData := []byte(data)
	dst := make([]byte, len(newData))
	switch method {
	case OpenSSLCipherMethodAes128Ecb, OpenSSLCipherMethodAes192Ecb, OpenSSLCipherMethodAes256Ecb:
		encrypter := newECBDecrypter(blockCipher)
		encrypter.CryptBlocks(dst, newData)
	case OpenSSLCipherMethodAes128Cbc, OpenSSLCipherMethodAes192Cbc, OpenSSLCipherMethodAes256Cbc:
		// CBC
	}
	switch options {
	case OpenSSLRawData, OpenSSLNormalData, OpenSSLNoPadding:
		newData = s.PKCS7UnPadding(dst)
	case OpenSSLZeroPadding:
		newData = s.PKCSZeroUnPadding(dst)
	}
	res = string(newData)
	return res, nil
}

func (s *Openssl) getKeyLength(method string) int {
	methodSlice := strings.Split(method, "-")
	if len(methodSlice) != 3 {
		return 0
	} else {
		if keyBit, err := strconv.Atoi(methodSlice[1]); err != nil {
			panic(err)
		} else {
			return keyBit / 8
		}
	}
}

func (s *Openssl) getKey(method, key string) string {
	keyLength := s.getKeyLength(method)
	curKeyLength := len(key)
	if curKeyLength < keyLength {
		return key + strings.Repeat("\x00", keyLength-curKeyLength)
	} else if curKeyLength > keyLength {
		return key[:keyLength]
	} else {
		return key
	}
}

func (s *Openssl) PKCSZeroUnPadding(data []byte) []byte {
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] != 0 {
			return data[:i+1]
		}
	}
	return []byte{}
}

// PKCS5UnPadding 对数据进行 PKCS5 反填充
func (s *Openssl) PKCS5UnPadding(data []byte) []byte {
	length := len(data)
	unpadding := int(data[length-1])
	return data[:(length - unpadding)]
}

// PKCSZeroPadding 对数据进行 0 填充
func (s *Openssl) PKCSZeroPadding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	plaintext := string(data)
	if padding != blockSize {
		plaintext += string(bytes.Repeat([]byte{0}, padding))
		return []byte(plaintext)
	} else {
		return data
	}
}

// PKCS7UnPadding 对数据进行 PKCS7 反填充
func (s *Openssl) PKCS7UnPadding(data []byte) []byte {
	length := len(data)
	unpadding := int(data[length-1])
	return data[:(length - unpadding)]
}

// PKCS5Padding 对数据进行 PKCS5 填充
func (s *Openssl) PKCS5Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	pad := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, pad...)
}

// PKCS7Padding 对数据进行 PKCS7 填充
func (s *Openssl) PKCS7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	pad := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, pad...)
}
