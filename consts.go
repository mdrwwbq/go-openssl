package openssl

var (
	CipherMethodAes128Cbc = "aes-128-cbc"
	CipherMethodAes192Cbc = "aes-192-cbc"
	CipherMethodAes256Cbc = "aes-256-cbc"
	CipherMethodAes128Ecb = "aes-128-ecb"
	CipherMethodAes192Ecb = "aes-192-ecb"
	CipherMethodAes256Ecb = "aes-256-ecb"

	CipherMethodMap = map[string]string{
		CipherMethodAes128Cbc: "AES-128-CBC",
		CipherMethodAes192Cbc: "AES-192-CBC",
		CipherMethodAes256Cbc: "AES-256-CBC",
		CipherMethodAes128Ecb: "AES-128-ECB",
		CipherMethodAes192Ecb: "AES-192-ECB",
		CipherMethodAes256Ecb: "AES-256-ECB",
	}

	NormalData  = 0 // 默认值就是PHP中options=0
	RawData     = 1 // php 的 OPENSSL_RAW_DATA （会用PKCS#7进行补位）
	ZeroPadding = 2 // php 的 OPENSSL_ZERO_PADDING
	NoPadding   = 3 // php 的 OPENSSL_NO_PADDING
)
