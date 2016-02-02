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

$realm = 'parallax';
$id = 'test';
$device = 'dev';

$sfc = new Crypto();
$db = new Database('sqlite');
$db->connect();

$sfa = new Authentication($db, $id, $realm);
$sfa->log_name = 'sfa';
$sfa->get_identity();

$sfa->log_name = 'sfa_badrealm';
$sfa->create_challenge($device);
$response = array(
    'nonce' => $sfa->challenge,
    'nonce_identity' => 'test',
    'nonce_signature' => $sfc->sign($sfa->challenge, $privkey),
    'realm' => 'badrealm',
    'device' => $device,
);

$verify = $sfa->verify_challenge_response($response);
assert('$verify == false', 'Challenge should fail to verify for bad realm');


$sfa->log_name = 'sfa_good';
$response = array(
    'nonce' => $sfa->challenge,
    'nonce_identity' => 'test',
    'nonce_signature' => $sfc->sign($sfa->challenge, $privkey),
    'realm' => $sfa->realm,
    'device' => $device,
);

$verify = $sfa->verify_challenge_response($response);
assert('$verify == true', 'Challenge did not verify');

$sfa->log_name = 'sfa_non_auth';
$sfa->create_challenge($device, $action = 'non_auth');
$response = array(
    'nonce' => $sfa->challenge,
    'nonce_identity' => 'test',
    'realm' => $sfa->realm,
    'device' => $device,
    'nonce_action' => 'non_auth',
);

$verify = $sfa->verify_challenge_response($response);
assert('$verify == true', 'Non-Auth challenge did not verify');

$sfa_invalid = new Authentication($db, "invalid!", "badidrealm");
$sfa_invalid->log_name = 'sfa_invalid';
$sfa_invalid->email = 'invalid!@email';
$sfa_invalid->get_identity();
assert('$sfa_invalid->sanity_check() == false', 'Input should not be valid for Auth object');


$sfa->log_name = 'sfa_token';
$seed = array('127.0.0.1');
$sfa->generate_auth_token($seed);
$expired_token = '123'.\Raindrops\AuthenticationConfig::TOKEN_SEPARATOR.'127.0.0.1';
$baddata_token = time().\Raindrops\AuthenticationConfig::TOKEN_SEPARATOR.'127.0.0.2';
$good_token = $sfa->token;


$sfa->log_name = 'sfa_expired_token';
$check_expired = $sfa->verify_auth_token($expired_token, $seed);
assert('$check_expired == false', 'Expired token should have failed verification');

$sfa->log_name = 'sfa_baddata_token';
$check_baddata = $sfa->verify_auth_token($baddata_token, $seed);
assert('$check_baddata == false', 'Bad data token should have failed verification');

$sfa->log_name = 'sfa_good_token';
$check_good = $sfa->verify_auth_token($good_token, $seed);
assert('$check_good == true', 'Good token did not verify');

$gbi = new Identity($db, null, null, 102);
$gbi->log_name = 'gbi';
$gbi->get_identity();
assert('$gbi->identity == "test"', 'Failed to get identity by id');


echo "Tests completed \r\n";
var_dump($db->log_tail());
var_dump($sfc->log_tail());
var_dump($sfa_invalid->log_tail());
var_dump($sfa->log_tail());
var_dump($gbi->log_tail());
?>
