<?php

namespace Util;

class Util
{
    /**
     * Encode data to Base64URL
     * @param string $data
     * @return string
     */
    static function base64url_encode(string $data): string
    {
        // First of all you should encode $data to Base64 string
        $b64 = base64_encode($data);

        // Convert Base64 to Base64URL by replacing “+” with “-” and “/” with “_”
        $url = strtr($b64, '+/', '-_');

        // Remove padding character from the end of line and return the Base64URL result
        return rtrim($url, '=');
    }

    /**
     * Decode data from Base64URL
     * @param string $data
     * @param boolean $strict
     * @return boolean|string
     */
    static function base64url_decode(string $data, bool $strict = false)
    {
        // Convert Base64URL to Base64 by replacing “-” with “+” and “_” with “/”
        $b64 = strtr($data, '-_', '+/');

        // Decode Base64 string and return the original data
        return base64_decode($b64, $strict);
    }

    /**
     * Get key fingerprint in SHA-256
     * @param $key
     * @return string
     */
    static function getPublicKeyFingerprint($key): string
    {
        return "SHA256:" . $key->getFingerprint("sha256");
    }
}