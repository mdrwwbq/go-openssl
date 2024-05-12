package openssl

import (
	"fmt"
	"strconv"
	"strings"
)

// CheckCipherMethodIsExist 判定加密/解密方法是否存在
func CheckCipherMethodIsExist(method string) bool {
	_, ok := CipherMethodMap[strings.ToLower(method)]
	return ok
}

func parseInt(val interface{}) (v int) {
	v = 0
	v, _ = strconv.Atoi(fmt.Sprintf("%v", val))
	return v
}
