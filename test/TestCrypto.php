<?php

require_once (__DIR__).'/../lib/Crypto.php';

use \Raindrops\Crypto;

$sfc = new Crypto();

$ec_privkey = <<<EOF
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIINZamMDsovqFsiMnciA6EewrwVaIstLmsqFLrf0JrwpoAoGCCqGSM49
AwEHoUQDQgAEPPBJ3Pd9cjGXfzx7bYJF8+DGweKKT83NZp/FxeKsigcTY3LKMlvy
3dJKZ6PY8CTr3vx20vM82nlEBvldcI72+g==
-----END EC PRIVATE KEY-----
EOF;

$ec_pubkey = <<<EOF
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPPBJ3Pd9cjGXfzx7bYJF8+DGweKK
T83NZp/FxeKsigcTY3LKMlvy3dJKZ6PY8CTr3vx20vM82nlEBvldcI72+g==
-----END PUBLIC KEY-----
EOF;

$ec_signature = $sfc->sign('ec test', $ec_privkey);
$ec_sig_verify = $sfc->verify_signature('ec test', $ec_signature, $ec_pubkey);
assert('$ec_sig_verify == true', 'EC Signature verification failed');

$sfc->generate_nonce('test');
$nonce1 = $sfc->nonce;
$sfc->generate_nonce('test');
$nonce2 = $sfc->nonce;
assert('strlen($nonce1) > 0', 'Invalid nonce generated');
assert('$nonce1 !== $nonce2', 'Nonce1 should not equal Nonce2');

$sfc->generate_nonce('test', array('chattr.ca','chrome39.0'), $add_salt = false);
$nonce1 = $sfc->nonce;
$sfc->generate_nonce('test', array('chattr.ca','chrome39.0'), $add_salt = false);
$nonce2 = $sfc->nonce;
assert('strlen($nonce1) > 0', 'Invalid nonce generated');
assert('$nonce1 === $nonce2', 'Nonce1 should equal Nonce2');


$keygen = $sfc->generate_keypair();
assert('$keygen == true', 'Failed to generate keypair');

$text = "shhh";
$encrypted = $sfc->pubkey_encrypt($sfc->public_key, $text);
$decrypted = $sfc->privkey_decrypt($sfc->private_key, $encrypted);
assert('$text === $decrypted', 'Text mismatch after encryption/decryption cycle');

$signature = $sfc->sign($text, $sfc->private_key);
$ret = $sfc->verify_signature($text, $signature, $sfc->public_key);
assert('$ret == 1', 'Signature verification failed');

$signature_fail1 = $sfc->verify_signature($text, $signature."x", $sfc->public_key);
assert('$signature_fail1 == 0', 'Signature verification should have failed (bad sig)');
$signature_fail2 = $sfc->verify_signature($text."x", $signature, $sfc->public_key);
assert('$signature_fail2 == 0', 'Signature verification should have failed (bad text)');

$thumbprint = $sfc->get_thumbprint($sfc->public_key);
assert('is_string($thumbprint) == true', 'Failed to generate thumbprint for public key');


//echo "Private key: \r\n" . $sfc->private_key . "\r\n\r\nPublic key: \r\n" . $sfc->public_key . "\r\n";

echo "Tests completed \r\n";
var_dump($sfc->log_tail(100));
?>
