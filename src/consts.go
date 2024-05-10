package src

var (
	OpenSSLCipherMethodAes128Cbc = "aes-128-cbc"
	OpenSSLCipherMethodAes192Cbc = "aes-192-cbc"
	OpenSSLCipherMethodAes256Cbc = "aes-256-cbc"
	OpenSSLCipherMethodAes128Ecb = "aes-128-ecb"
	OpenSSLCipherMethodAes192Ecb = "aes-192-ecb"
	OpenSSLCipherMethodAes256Ecb = "aes-256-ecb"

	OpenSSLCipherMethodMap = map[string]string{
		OpenSSLCipherMethodAes128Cbc: "AES-128-CBC",
		OpenSSLCipherMethodAes192Cbc: "AES-192-CBC",
		OpenSSLCipherMethodAes256Cbc: "AES-256-CBC",
		OpenSSLCipherMethodAes128Ecb: "AES-128-ECB",
		OpenSSLCipherMethodAes192Ecb: "AES-192-ECB",
		OpenSSLCipherMethodAes256Ecb: "AES-256-ECB",
	}

	OpenSSLNormalData  = 0 // 默认值就是PHP中options=0
	OpenSSLRawData     = 1 // php 的 OPENSSL_RAW_DATA （会用PKCS#7进行补位）
	OpenSSLZeroPadding = 2 // php 的 OPENSSL_ZERO_PADDING
	OpenSSLNoPadding   = 3 // php 的 OPENSSL_NO_PADDING
)
