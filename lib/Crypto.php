<?php namespace Raindrops;
/**
 * Raindrops Framework
 *
 * @author  Adrian@Slacknet
 * @license http://www.gnu.org/licenses/gpl-3.0.txt GPLv3
 */

require_once (__DIR__).'/Object.php';

class Crypto extends Object {
    const NONCE_HASH_ALGO = 'sha256';
    const THUMBPRINT_HASH_ALGO = 'sha1';
    const SIG_ALGO = 'RSA-SHA256';
    const KEYGEN_KEYTYPE = OPENSSL_KEYTYPE_RSA;

    public $private_key = '';
    public $public_key = '';
    public $nonce = '';
    private $keygen = null;

    final public function __construct() {
        //
    }

    public function generate_keypair() {
        $openssl_config = array(
            //'config' => getenv('OPENSSL_CONF'), // this is so stupid
            'config' => (__DIR__).'/openssl.cnf',
            'private_key_bits' => 2048,
            'private_key_type' => Crypto::KEYGEN_KEYTYPE,
        );

        $this->keygen = openssl_pkey_new($openssl_config); // needs 'config' parameter

        if ($this->keygen == 0) {
            $this->get_openssl_errors();
            $this->log("Keygen failed to create keypair", 3);
            return false;
        }

        // get the private key
        openssl_pkey_export($this->keygen, $pkey, null, $openssl_config); // needs 'config' parameter

        // get the public key
        $keygen_details = openssl_pkey_get_details($this->keygen);
        $this->public_key = $keygen_details['key'];
        $this->private_key = $pkey;

        // free resources
        openssl_pkey_free($this->keygen);

        $this->log("Keygen was successful", 1);
        $this->log("Public key: " . $this->public_key, 0);
        $this->log("Private key: " . $this->private_key, 0);
        return true;
    }

    public function pubkey_encrypt($pubkey, $data) {
        $crypted = null;

        $pubkey = $this->fix_pem_format($pubkey);
        if ($this->validate_key($pubkey, 'public')) {
            openssl_public_encrypt($data, $crypted, $pubkey);
        }
        return base64_encode($crypted);
    }

    public function privkey_decrypt($privkey, $data) {
        $decrypted = null;

        $privkey = $this->fix_pem_format($privkey);
        if ($this->validate_key($privkey, 'private')) {
            $decoded_data = base64_decode($data);

            openssl_private_decrypt($decoded_data, $decrypted, $privkey);
        }
        return $decrypted;
    }

    public function sign($data, $privkey) {
        $signature = null;

        $privkey = $this->fix_pem_format($privkey);
        if ($this->validate_key($privkey, 'private')) {
            openssl_sign($data, $signature, $privkey, Crypto::SIG_ALGO);
        }
        return base64_encode($signature);
    }

    public function verify_signature($data, $signature, $pubkey) {
        $decoded_signature = base64_decode($signature);

        $pubkey = $this->fix_pem_format($pubkey);
        if (! $this->validate_key($pubkey, 'public')) {
            return false;
        }

        $verify_result = openssl_verify($data, $decoded_signature, $pubkey, Crypto::SIG_ALGO);

        switch ($verify_result) {
            case 1:
                $this->log("Signature is valid for '$data'", 1);
                return true;
            break;

            case 0:
                $this->log("Signature is invalid for '$data'", 1);
                return false;
            break;
        }

        $this->get_openssl_errors();
        $this->log("Signature verification failed '$data' (return: $verify_result)", 3);
        return false;
    }

    public function generate_nonce($nonce_identity, $seed = array(), $add_salt = true) {
        $nonce = ($add_salt ? mcrypt_create_iv(16) : '') . $nonce_identity . join('', $seed);

        $this->nonce = hash(Crypto::NONCE_HASH_ALGO, $nonce, false);
        return true;
    }

    public function validate_key(& $key, $keytype = 'public') {
        $resource = null;

        switch ($keytype) {
            case 'private':
                $resource = openssl_pkey_get_private($key);
            break;
            case 'public':
                $resource = openssl_pkey_get_public($key);
            break;
        }

        if ($resource != false) {
            $this->log("Validation successful for '". $keytype ."' key (resource: " . $resource . ")", 1);
            openssl_free_key($resource);
            return true;
        }

        $this->get_openssl_errors();
        $this->log("Validation failed for '". $keytype ."' key", 3);
        return false;
    }

    public function get_thumbprint($pubkey) {
        $pubkey = $this->fix_pem_format($pubkey);
        if ($this->validate_key($pubkey, 'public')) {
            return hash(Crypto::THUMBPRINT_HASH_ALGO, $pubkey, false);
        }
        return null;
    }

    public function get_openssl_errors() {
        $error_msg = null;
        while ($error_msg = openssl_error_string()) {
            $this->log("OpenSSL error: $error_msg", 0);
        }

        $this->log("OPENSSL_CONF = ". getenv('OPENSSL_CONF'), 0);
    }

    public function fix_pem_format($key) {
        $key = preg_replace('/[^a-z0-9\s\+\=\/\-]/ui','',str_replace(array("\r","\n"), '', $key));
        $begin_tag = strtoupper(preg_replace('/^.*(BEGIN.+?KEY).*$/sui', '$1', $key));
        $base64 = preg_replace('/^([-]*)(BEGIN[a-z\s]+KEY)([-])*([a-z0-9\/\+\=]+)([-])*(END[a-z\s]+KEY)([-])*$/ui', '$4', $key);
        $base64 = chunk_split($base64, 64, "\n");
        $end_tag = strtoupper(preg_replace('/^.*(END.+?KEY).*$/sui', '$1', $key));

        $clean = "-----$begin_tag-----\n$base64-----$end_tag-----\n";

        return $clean;
    }
}

?>
