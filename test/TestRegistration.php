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

$sfr_exists = new Registration($db, 'test', 'slacknet');
$sfr = new Registration($db, 'newtest', 'chattr');

$good_id = array(
    'pubkey' => $pubkey,
);

$bad_id = array(
    'pubkey' => $badpubkey,
);

$good_identity = $sfr->create_identity($good_id);
assert('$good_identity == true', 'Failed to create identity');
$identity_delete = $sfr->delete_identity();
assert('$identity_delete == true', 'Failed to delete identity');

$bad_identity = $sfr->create_identity($bad_id);
assert('$bad_identity == false', 'Identity creation should have failed');

$identity_exists = $sfr_exists->create_identity($good_id);
assert('$identity_exists == false', 'Identity creation should have failed (already exists)');


echo "Tests completed \r\n";
var_dump($db->log_tail());
var_dump($sfr->log_tail());
var_dump($sfr_exists->log_tail());
?>
