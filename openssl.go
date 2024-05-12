package openssl

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
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
	newIv := s.getIv(extParams.iv)
	blockCipher, err := aes.NewCipher(s.getKey(method, key))
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
		encrypt := newECBEncrypter(blockCipher)
		encrypt.CryptBlocks(dst, newData)
	case CipherMethodAes128Cbc, CipherMethodAes192Cbc, CipherMethodAes256Cbc:
		// CBC
		encrypt := cipher.NewCBCEncrypter(blockCipher, newIv)
		encrypt.CryptBlocks(dst, newData)
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
	blockCipher, err := aes.NewCipher(s.getKey(method, key))
	if err != nil {
		return "", err
	}
	newData := []byte(data)
	newIv := s.getIv(extParams.iv)
	dst := make([]byte, len(newData))
	switch method {
	case CipherMethodAes128Ecb, CipherMethodAes192Ecb, CipherMethodAes256Ecb:
		decrypt := newECBDecrypter(blockCipher)
		decrypt.CryptBlocks(dst, newData)
	case CipherMethodAes128Cbc, CipherMethodAes192Cbc, CipherMethodAes256Cbc:
		// CBC
		decrypt := cipher.NewCBCDecrypter(blockCipher, newIv)
		decrypt.CryptBlocks(dst, newData)

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

// getKey 根据aes.BlockSize获得新的key
// 如果key长度不够，将进行追加\x00 -> \0 -> chr(0)
func (s *Openssl) getKey(method, key string) []byte {
	keyLength := s.getKeyLength(method)
	curKeyLength := len(key)
	res := key
	if curKeyLength < keyLength {
		res += strings.Repeat("\x00", keyLength-curKeyLength)
	} else if curKeyLength > keyLength {
		res = key[:keyLength]
	}
	return []byte(res)
}

// getIv 根据aes.BlockSize获得新的Iv
// 如果iv长度不够，将进行追加\x00 -> \0 -> chr(0)
func (s *Openssl) getIv(iv string) []byte {
	curIvLength := len(iv)
	res := iv
	if curIvLength < aes.BlockSize {
		res += strings.Repeat("\x00", aes.BlockSize-curIvLength)
	} else if curIvLength > aes.BlockSize {
		res = iv[:aes.BlockSize]
	}
	return []byte(res)
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
