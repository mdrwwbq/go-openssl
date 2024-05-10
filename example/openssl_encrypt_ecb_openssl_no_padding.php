<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);


$key = "1234567890123456"; // key
$data = "222"; // data
$iv = ""; // ECB does not support iv
$options = OPENSSL_NO_PADDING; // data padding mode

function PKCS7Padding($data, $method) {
    // aes block size is 16
    $blockSize = 16;
    $padding = $blockSize - strlen($data) % $blockSize;
    if ( $padding != $blockSize ) {
        $pad = str_repeat(chr($padding), $padding);
        $data = $data . $pad;
    }
    /*for($i=0;$i<strlen($res);$i++) {
        echo ord($res[$i]). ' ';
    }*/
    return $data;
}

// ecb 128
echo str_repeat("-", 50) . PHP_EOL;
$encrypted = base64_encode(openssl_encrypt(PKCS7Padding($data, 'AES-128-ECB'), 'AES-128-ECB', $key, $options, $iv));
echo sprintf("AES-128-ECB options=%d result：%s%s", $options, $encrypted, PHP_EOL);
echo str_repeat("-", 50) . PHP_EOL;
// ecb 192
// notice aes-192-ecb key length = 24
// php default appends 0x00 to the end of the key
$encrypted = base64_encode(openssl_encrypt(PKCS7Padding($data, 'AES-192-ECB'), 'AES-192-ECB', $key, $options, $iv));
echo sprintf("AES-192-ECB options=%d result：%s%s", $options, $encrypted, PHP_EOL);
echo str_repeat("-", 50) . PHP_EOL;
// ecb 256
// notice aes-256-ecb key length = 32
// php default appends 0x00 to the end of the key
$encrypted = base64_encode(openssl_encrypt(PKCS7Padding($data, 'AES-256-ECB'), 'AES-256-ECB', $key, $options, $iv));
echo sprintf("AES-256-ECB options=%d result：%s%s", $options, $encrypted, PHP_EOL);
echo str_repeat("-", 50) . PHP_EOL;

