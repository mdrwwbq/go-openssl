<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);

$method_map = [
    'AES-128-ECB'   =>  16,
    'AES-192-ECB'   =>  24,
    'AES-256-ECB'   =>  32,
];

$key = "123"; // key
$data = "ESxnVJjbMJhD2I6MW4KtAg=="; // data
$iv = ""; // ECB does not support iv
// notice openssl_encrypt default options = 0,but openssl_decrypt options = OPENSSL_RAW_DATA
$options = OPENSSL_RAW_DATA; // data padding mode
$data = base64_decode($data);
echo openssl_decrypt($data, 'AES-128-ECB', padKey($key, 'AES-128-ECB'), $options, $iv);
// AES-192-ECB
// AES-256-ECB
// ...
function padKey($key, $method) {
    global $method_map;
    $key_length = $method_map[$method];
    if (strlen($key) < $key_length) {
        $key = str_pad($key, $key_length, "\x00");
    }
    return $key;
}