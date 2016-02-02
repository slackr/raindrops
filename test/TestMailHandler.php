<?php

require_once (__DIR__).'/../controller/MailHandler.php';

use \Raindrops\MailHandler;

$mh = new \Raindrops\MailHandler();
$mh->to = 'ap@slacknet.ca';
$mh->from = 'no-reply@echoes.im';
$mh->from_name = 'Parallax Identity Test';
$mh->subject = 'Test message';
$mh->message = 'Test message body';

$mail_sent = $mh->send($as_html = true);

echo "Tests completed \r\n";
var_dump($mh->log_tail());
?>
