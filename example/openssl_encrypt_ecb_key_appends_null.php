<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);


$method_map = [
    'AES-128-ECB'   =>  16,
    'AES-192-ECB'   =>  24,
    'AES-256-ECB'   =>  32,
];

$key = "123"; // key
$data = "222"; // data
$iv = ""; // ECB does not support iv
$options = 0; // data padding mode

// ecb 128
echo str_repeat("-", 50) . PHP_EOL;
$encrypted = openssl_encrypt($data, 'AES-128-ECB', padKey($key, 'AES-128-ECB'), $options, $iv);
echo sprintf("AES-128-ECB options=%d result：%s%s", $options, $encrypted, PHP_EOL);
echo str_repeat("-", 50) . PHP_EOL;


function padKey($key, $method) {
    global $method_map;
    $key_length = $method_map[$method];
    if (strlen($key) < $key_length) {
        $key = str_pad($key, $key_length, "\x00");
    }
    return $key;
}