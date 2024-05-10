<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);


$key = "1234567890123456"; // key
$data = "222"; // data
$iv = ""; // ECB does not support iv
$options = OPENSSL_RAW_DATA; // data padding mode
// ecb 128
echo str_repeat("-", 50) . PHP_EOL;
$encrypted = base64_encode(openssl_encrypt($data, 'AES-128-ECB', $key, $options, $iv));
echo sprintf("AES-128-ECB options=%d result：%s%s", $options, $encrypted, PHP_EOL);
echo str_repeat("-", 50) . PHP_EOL;
/// ecb 192
 // notice aes-192-ecb key length = 24
 // php default appends 0x00 to the end of the key
$encrypted = base64_encode(openssl_encrypt($data, 'AES-192-ECB', $key, $options, $iv));
echo sprintf("AES-192-ECB options=%d result：%s%s", $options, $encrypted, PHP_EOL);
echo str_repeat("-", 50) . PHP_EOL;
// ecb 256
// notice aes-256-ecb key length = 32
// php default appends 0x00 to the end of the key
$encrypted = base64_encode(openssl_encrypt($data, 'AES-256-ECB', $key, $options, $iv));
echo sprintf("AES-256-ECB options=%d result：%s%s", $options, $encrypted, PHP_EOL);
echo str_repeat("-", 50) . PHP_EOL;

