<?php

require_once (__DIR__).'/../model/Database.php';
require_once (__DIR__).'/../controller/Registration.php';

use \Raindrops\Database;
use \Raindrops\Registration;

$pubkey = <<<EOF
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPPBJ3Pd9cjGXfzx7bYJF8+DGweKK
T83NZp/FxeKsigcTY3LKMlvy3dJKZ6PY8CTr3vx20vM82nlEBvldcI72+g==
-----END PUBLIC KEY-----
EOF;

$badpubkey = 'u wot m8';

$db = new Database('mysql');
$db->connect();

$sfr_exists = new Registration($db, 'test', 'parallax');
$sfr = new Registration($db, 'newtest', 'chattr');

$good_id = array(
    'pubkey' => $pubkey,
    'email' => 'test@test.ca',
    'device' => 'dev',
);

$bad_pubkey = array(
    'pubkey' => $badpubkey,
    'email' => 'test@test.ca',
    'device' => 'dev',
);

$bad_email = array(
    'pubkey' => $pubkey,
    'email' => 'u wot m8',
    'device' => 'dev',
);

$bad_device = array(
    'pubkey' => $pubkey,
    'email' => 'test@test.ca',
    'device' => '',
);

$sfr->log_name = 'good_id';
$good_identity = $sfr->create_identity($good_id);
assert('$good_identity == true', 'Failed to create identity');

$sfr->log_name = 'good_id_delete_id';
$identity_delete = $sfr->delete_identity();
assert('$identity_delete == true', 'Failed to delete identity');


$sfr->log_name = 'bad_pubkey';
$bad_identity = $sfr->create_identity($bad_pubkey);
assert('$bad_identity == false', 'Identity creation should have failed (bad pubkey)');

$sfr->log_name = 'bad_email';
$bad_identity_email = $sfr->create_identity($bad_email);
assert('$bad_identity_email == false', 'Identity creation should have failed (bad email)');

$sfr->log_name = 'bad_device';
$bad_identity_device = $sfr->create_identity($bad_device);
assert('$bad_identity_device == false', 'Identity creation should have failed (bad device)');


$sfr_exists->log_name = 'sfr_exists';
$identity_exists = $sfr_exists->create_identity($good_id);
assert('$identity_exists == false', 'Identity creation should have failed (already exists)');


echo "Tests completed \r\n";
var_dump($db->log_tail());
var_dump($sfr->log_tail());
var_dump($sfr_exists->log_tail());
?>
