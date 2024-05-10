package openssl

import (
	"bytes"
	"context"
	"crypto/aes"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type Openssl struct {
	ctx context.Context
}
type opensslArgs struct {
	options   int
	iv        string
	tag       string // Unrealized
	aad       string // Unrealized
	tagLength int    // Unrealized
}

func NewOpenssl(ctx context.Context) *Openssl {
	return &Openssl{ctx: ctx}
}

// Encrypt 加密
func (s *Openssl) Encrypt(data, method, key string, args ...interface{}) (res string, err error) {
	res = ""
	extParams := s.parseArgs(args...)
	if !CheckCipherMethodIsExist(method) {
		return "", errors.New("cipher method is not exist")
	}
	newKey := s.getKey(method, key)
	blockCipher, err := aes.NewCipher([]byte(newKey))
	if err != nil {
		return "", err
	}
	newData := []byte(data)

	switch extParams.options {
	case RawData:
		newData = s.PKCS7Padding(newData, blockCipher.BlockSize())
	case ZeroPadding:
		newData = s.PKCSZeroPadding(newData, blockCipher.BlockSize())
	case NormalData, NoPadding:
		newData = s.PKCS7Padding(newData, blockCipher.BlockSize())
	}
	dst := make([]byte, len(newData))
	switch method {
	case CipherMethodAes128Ecb, CipherMethodAes192Ecb, CipherMethodAes256Ecb:
		// ECB
		encrypter := newECBEncrypter(blockCipher)
		encrypter.CryptBlocks(dst, newData)
	case CipherMethodAes128Cbc, CipherMethodAes192Cbc, CipherMethodAes256Cbc:
		// CBC
	}
	switch extParams.options {
	case RawData, NoPadding, ZeroPadding:
		res = string(dst)
	default:
		res = base64.StdEncoding.EncodeToString(dst)
	}
	return res, nil
}

// Decrypt 解密
func (s *Openssl) Decrypt(data, method, key string, args ...interface{}) (res string, err error) {
	if data == "" {
		return "", nil
	}
	extParams := s.parseArgs(args...)
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
	case CipherMethodAes128Ecb, CipherMethodAes192Ecb, CipherMethodAes256Ecb:
		encrypter := newECBDecrypter(blockCipher)
		encrypter.CryptBlocks(dst, newData)
	case CipherMethodAes128Cbc, CipherMethodAes192Cbc, CipherMethodAes256Cbc:
		// CBC
	}
	switch extParams.options {
	case RawData, NormalData, NoPadding:
		newData = s.PKCS7UnPadding(dst)
	case ZeroPadding:
		newData = s.PKCSZeroUnPadding(dst)
	}
	res = string(newData)
	return res, nil
}

// parseArgs
func (s *Openssl) parseArgs(args ...interface{}) (res *opensslArgs) {
	res = &opensslArgs{}
	argsLen := len(args)
	if argsLen >= 1 {
		res.options = parseInt(args[0])
	}
	if argsLen >= 2 {
		res.iv = fmt.Sprintf("%v", args[1])
	}
	// ... other args Unrealized
	return res
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
