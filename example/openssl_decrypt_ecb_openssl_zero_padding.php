<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);


$key = "1234567890123456"; // key
$data = "/NCcLXFd+v8a3SwFF79/WA=="; // data
$iv = ""; // ECB does not support iv
$options = OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING; // data padding mode
$data = base64_decode($data);
var_dump(PKCSZeroUnPadding(openssl_decrypt($data, 'AES-128-ECB', $key, $options, $iv)));
// AES-192-ECB
// AES-256-ECB
// ...
function PKCSZeroUnPadding($data) {
    $length = strlen($data);
    for ($i = $length - 1; $i >= 0; $i--) {
        if ($data[$i] !== "\x00") {
            return substr($data, 0, $i + 1);
        }
    }
    return "";
}
