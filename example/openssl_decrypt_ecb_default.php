<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);


$key = "1234567890123456"; // key
$data = "Q0vftwpmFHJfzUQbjV18DQ=="; // data
$iv = ""; // ECB does not support iv
// notice openssl_encrypt default options = 0,but openssl_decrypt options = OPENSSL_RAW_DATA
$options = OPENSSL_RAW_DATA; // data padding mode
$data = base64_decode($data);
echo openssl_decrypt($data, 'AES-128-ECB', $key, $options, $iv);
// AES-192-ECB
// AES-256-ECB
// ...