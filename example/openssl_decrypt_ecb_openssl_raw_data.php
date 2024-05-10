<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);


$key = "1234567890123456"; // key
$data = "Q0vftwpmFHJfzUQbjV18DQ=="; // data
$iv = ""; // ECB does not support iv
$options = OPENSSL_RAW_DATA; // data padding mode
$data = base64_decode($data);
echo openssl_decrypt($data, 'AES-128-ECB', $key, $options, $iv);
// AES-192-ECB
// AES-256-ECB
// ...