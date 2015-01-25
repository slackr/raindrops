<?php

require_once (__DIR__).'/../lib/Crypto.php';
require_once (__DIR__).'/../model/Database.php';
require_once (__DIR__).'/../controller/Authentication.php';
require_once (__DIR__).'/../controller/Identity.php';

use \Raindrops\Crypto;
use \Raindrops\Database;
use \Raindrops\Authentication;
use \Raindrops\Identity;

$privkey = <<<EOF
-----BEGIN EC PRIVATE KEY-----MHcCAQEEIINZamMDsovqFsiMnciA6EewrwVaIstLmsqFLrf0JrwpoAoGCCqGSM49AwEHoUQDQgAEPPBJ3Pd9cjGXfzx7bYJF8+DGweKKT83NZp/FxeKsigcTY3LKMlvy3dJKZ6PY8CTr3vx20vM82nlEBvldcI72+g==-----END EC PRIVATE KEY-----
EOF;

$realm = 'slacknet';
$id = 'test';

$sfc = new Crypto();
$db = new Database('mysql');
$db->connect();

$sfa = new Authentication($db, $id, $realm);
$sfa->get_identity();

$sfa->create_challenge();
$response = array(
    'nonce' => $sfa->challenge,
    'nonce_identity' => 'test',
    'nonce_signature' => $sfc->sign($sfa->challenge, $privkey),
    'realm' => 'badrealm',
);

$verify = $sfa->verify_challenge_response($response);
assert('$verify == false', 'Challenge should fail to verify for bad realm');

$response = array(
    'nonce' => $sfa->challenge,
    'nonce_identity' => 'test',
    'nonce_signature' => $sfc->sign($sfa->challenge, $privkey),
    'realm' => $sfa->realm,
);

$verify = $sfa->verify_challenge_response($response);
assert('$verify == true', 'Challenge did not verify');

$sfa_invalid = new Authentication($db, "invalid!", "badidrealm");
$sfa_invalid->get_identity();
assert('$sfa_invalid->sanity_check() == false', 'Input should not be valid for Auth object');

$seed = array('127.0.0.1');
$sfa->generate_auth_token($seed);
$expired_token = '123'.\Raindrops\AuthenticationConfig::TOKEN_SEPARATOR.'127.0.0.1';
$baddata_token = time().\Raindrops\AuthenticationConfig::TOKEN_SEPARATOR.'127.0.0.2';
$good_token = $sfa->token;

$check_expired = $sfa->verify_auth_token($expired_token, $seed);
$check_baddata = $sfa->verify_auth_token($baddata_token, $seed);
$check_good = $sfa->verify_auth_token($good_token, $seed);
assert('$check_expired == false', 'Expired token should have failed verification');
assert('$check_baddata == false', 'Bad data token should have failed verification');
assert('$check_good == true', 'Good token did not verify');

$gbi = new Identity($db, null, null, 1);
$gbi->get_identity();
assert('$gbi->identity == "test"', 'Failed to get identity by id');


echo "Tests completed \r\n";
var_dump($db->log_tail());
var_dump($sfc->log_tail());
var_dump($sfa_invalid->log_tail());
var_dump($sfa->log_tail());
var_dump($gbi->log_tail());
?>
