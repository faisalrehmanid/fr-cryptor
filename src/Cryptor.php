<?php

namespace FR\Cryptor;

/**
 * @author Faisal Rehman <faisalrehmanid@hotmail.com>
 * 
 * This class provide abstraction layer of encryption and decryption 
 * and always create object of type \FR\Cryptor\CryptorInterface
 * 
 * Example: How to use this class?
 * 
 * ```
 * <?php
 *   $config =  array('encrypt_method' => 'AES-256-CBC',
 *                    'iterations' => 999);
 *   $cryptor = new \FR\Cryptor\Cryptor($config);
 *   $string = 'Sample string'; $key = 'sample-key';
 *   $encrypted_string = $cryptor->encrypt($string, $key);
 *   $orignal_string = $cryptor->encrypt($encrypted_string, $key);
 * ?>
 * ```
 */

class Cryptor implements CryptorInterface
{
    /**
     * Encrypt method
     *
     * Recommended methods: AES-128-CBC | AES-192-CBC | AES-256-CBC
     * @link http://php.net/manual/en/function.openssl-get-cipher-methods.php List of available encrypt methods
     * @var string
     */
    protected $encrypt_method;

    /**
     * Number of iterations to create complexity
     * More iterations means more processing
     *
     * @var int
     */
    protected $iterations;

    /**
     * Create object of \FR\Cryptor\CryptorInterface
     * 
     * // Cryptor configuration
     * $config =  array('encrypt_method' => 'AES-256-CBC',
     *                  'iterations' => 999);
     * Recommended methods: AES-128-CBC | AES-192-CBC | AES-256-CBC
     * 
     * @param array $config Cryptor configuration
     * @link http://php.net/manual/en/function.openssl-get-cipher-methods.php List of available encrypt methods
     * @throws \Exception `encrypt_method` is required in $config
     * @return object \FR\Cryptor\CryptorInterface
     */
    public function __construct(array $config)
    {
        @$encrypt_method = $config['encrypt_method'];
        @$iterations = $config['iterations'];

        if (!$encrypt_method)
            throw new \Exception('`encrypt_method` is required in $config');

        if (!$iterations || !is_int($iterations))
            throw new \Exception('`iterations` is required in $config must be integer');

        $this->encrypt_method = $encrypt_method;
        $this->iterations = $iterations;
    }

    /**
     * Get encrypt method length number: 128 | 192 | 256
     * @return int length
     */
    protected function encryptMethodLength()
    {
        $number = filter_var($this->encrypt_method, FILTER_SANITIZE_NUMBER_INT);

        return intval(abs($number));
    }

    /**
     * Apply encryption to the given string
     * @param string $string String to be encrypt
     * @param string $key Use to encrypt string
     * @return string Encrypted string
     */
    public function encrypt($string, $key)
    {
        $iv_length = openssl_cipher_iv_length($this->encrypt_method);
        $iv = openssl_random_pseudo_bytes($iv_length);

        $salt = openssl_random_pseudo_bytes(256);
        $hash_key = hash_pbkdf2('sha512', $key, $salt, $this->iterations, ($this->encryptMethodLength() / 4));

        $encrypted_string = openssl_encrypt(
            $string,
            $this->encrypt_method,
            hex2bin($hash_key),
            OPENSSL_RAW_DATA,
            $iv
        );

        $encrypted_string = base64_encode($encrypted_string);
        unset($hash_key);

        $output = [
            'ciphertext' => $encrypted_string,
            'iv'         => bin2hex($iv),
            'salt'       => bin2hex($salt),
            'iterations' => $this->iterations,
        ];
        unset($encrypted_string, $iv, $iv_length, $salt);

        return base64_encode(json_encode($output));
    }

    /**
     * Decrypt the given encrypted string
     * @param string $encrypted_string Encrypted string that is base64 encoded
     * @param string $key Use to decrypt string
     * @return mixed Original string
     */
    public function decrypt($encrypted_string, $key)
    {
        $json = json_decode(base64_decode($encrypted_string), true);

        try {
            $salt = hex2bin($json["salt"]);
            $iv = hex2bin($json["iv"]);
        } catch (\Exception $e) {
            return null;
        }

        $cipher_text = base64_decode($json['ciphertext']);

        $iterations = intval(abs($json['iterations']));
        $hash_key = hash_pbkdf2('sha512', $key, $salt, $iterations, ($this->encryptMethodLength() / 4));
        unset($iterations, $json, $salt);

        $decrypted = openssl_decrypt(
            $cipher_text,
            $this->encrypt_method,
            hex2bin($hash_key),
            OPENSSL_RAW_DATA,
            $iv
        );
        unset($cipher_text, $hash_key, $iv);

        return $decrypted;
    }
}
