<?php
// Example code
include_once('./../../../autoload.php');

/**
 * Pretty print array/object for debuging
 *
 * @param array|object $params Array/object to be print
 * @param boolean $exit Exit after print
 * @return void
 */
if (!function_exists('\pr')) {
    function pr($params, $exit = true)
    {
        echo "<pre>";
        print_r($params);
        echo "</pre>";

        if ($exit == true) {
            exit();
        }
    }
}

// Create $cryptor object
$config =  array(
    'encrypt_method' => 'AES-256-CBC',
    'iterations' => 999
);
$cryptor = new \FR\Cryptor\Cryptor($config);
?>

<!DOCTYPE html>
<html>

<body>
    <?php
    // How to check instance type
    if ($cryptor instanceof \FR\Cryptor\CryptorInterface)
        echo 'How to check instance type: \FR\Cryptor\CryptorInterface <br>';

    // How to encrypt
    $string = 'Encrypt this string from PHP';
    $key = '123';
    $encrypted_string = $cryptor->encrypt($string, $key);
    echo '<b>Encrypted string from PHP:</b> ' . $encrypted_string;
    echo '<br>';

    // How to decrypt
    $orignal_string = $cryptor->decrypt($encrypted_string, $key);
    echo '<b>Orignal string decrypt from PHP:</b> ' . $orignal_string;
    echo '<br>';
    ?>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.9-1/crypto-js.js"></script>
    <script src="./js/fr-cryptor.js"></script>
    <script>
        // TODO: fr-cryptor should work on config itrations and encrypt_methods
        var string = 'Encrypt this string from JS';
        var key = '456';

        let cryptor = new FRCryptor();
        var encrypted_string = cryptor.encrypt(string, key);
        console.log('Encrypted string from JS');
        console.log(encrypted_string);

        var orignal_string = cryptor.decrypt(encrypted_string, key);
        console.log('Orignal string decrypt from JS');
        console.log(orignal_string);

        var orignal_string = cryptor.decrypt('<?php echo $encrypted_string; ?>', '<?php echo $key; ?>');
        console.log('Orignal string of PHP decrypted from JS');
        console.log(orignal_string);
    </script>
</body>

</html>