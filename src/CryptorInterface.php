<?php

namespace FR\Cryptor;

interface CryptorInterface
{
    /**
     * Apply encryption to the given string
     * @param string $string String to be encrypt
     * @param string $key Use to encrypt string
     * @return string Encrypted string
     */
    public function encrypt($string, $key);

    /**
     * Decrypt the given encrypted string
     * @param string $encrypted_string Encrypted string that is base64 encoded
     * @param string $key Use to decrypt string
     * @return mixed Original string
     */
    public function decrypt($encrypted_string, $key);
}
