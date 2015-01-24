<?php

require_once (__DIR__).'/../model/Database.php';

use \Raindrops\Database;

$o = new Database('mysql');
$o->connect();

assert('$o->connected == true', 'Database not connected');

$o->query("select * from rd_identities", array(), 3);
assert('is_string($o->query) == true', 'Query was not prepared successfully');

echo "Tests completed \r\n";
var_dump($o->log_tail());
?>
