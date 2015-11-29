<?php

require_once (__DIR__).'/../model/Database.php';

use \Raindrops\Database;

$o = new Database('sqlite');
$o->connect();

assert('$o->connected == true', 'Database not connected');

$ret = $o->query("select * from rd_identities", array(), 3);
assert('is_string($o->query) == true', 'Query was not prepared successfully');
assert('$ret == true', 'Query did not execute successfully');

echo "Tests completed \r\n";
var_dump($o->log_tail());
?>
