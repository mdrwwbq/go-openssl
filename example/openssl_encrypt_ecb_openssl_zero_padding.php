<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);


$key = "1234567890123456"; // key
$data = "222"; // data
$iv = ""; // ECB does not support iv
$options = OPENSSL_ZERO_PADDING; // data padding mode

function padData($data, $method) {

    list($type, $blockSize, $options) = explode('-', $method);
    $blockSize = $blockSize / 8;
    $padding = $blockSize - strlen($data)%$blockSize;
    if ( $padding != $blockSize ) {
        $data = str_pad($data, 16, "\0");
    }
    return $data;
}
// ecb 128
echo str_repeat("-", 50) . PHP_EOL;
$encrypted = (openssl_encrypt(padData($data, 'AES-128-ECB'), 'AES-128-ECB', $key, $options, $iv));
echo sprintf("AES-128-ECB options=%d result：%s%s", $options, $encrypted, PHP_EOL);
echo str_repeat("-", 50) . PHP_EOL;
// ecb 192
// notice aes-192-ecb key length = 24
// php default appends 0x00 to the end of the key
$encrypted = (openssl_encrypt(padData($data, 'AES-192-ECB'), 'AES-192-ECB', $key, $options, $iv));
echo sprintf("AES-192-ECB options=%d result：%s%s", $options, $encrypted, PHP_EOL);
echo str_repeat("-", 50) . PHP_EOL;
// ecb 256
// notice aes-256-ecb key length = 32
// php default appends 0x00 to the end of the key
$encrypted = (openssl_encrypt(padData($data, 'AES-256-ECB'), 'AES-256-ECB', $key, $options, $iv));
echo sprintf("AES-256-ECB options=%d result：%s%s", $options, $encrypted, PHP_EOL);
echo str_repeat("-", 50) . PHP_EOL;

