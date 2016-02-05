<?php

require_once (__DIR__).'/../controller/SessionHandler.php';

use \Raindrops\SessionHandler;

$sh = new \Raindrops\SessionHandler();

$xff1 = "127.0.0.1:1234";
$xff2 = "127.0.0.1, 127.0.0.2, 127.0.0.3:1234, 127.0.0.4";
$bad_xff1 = ":1234";
$bad_xff2 = ":";
$bad_xff3 = "123,,123,,123:1234";

$xff = $sh->clean_xff_header($xff1);
assert('$xff == "127.0.0.1"');

$xff = $sh->clean_xff_header($xff2);
assert('$xff == "127.0.0.1, 127.0.0.2, 127.0.0.3, 127.0.0.4"');

$xff = $sh->clean_xff_header($bad_xff1);
assert('$xff == ""');

$xff = $sh->clean_xff_header($bad_xff2);
assert('$xff == ""');

$xff = $sh->clean_xff_header($bad_xff3);
assert('$xff == "123,,123,,123"');

echo "Tests completed \r\n";
var_dump($sh->log_tail());
?>
