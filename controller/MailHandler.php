<?php namespace Raindrops;
/**
 * Raindrops Framework
 *
 * @author  Adrian@Slacknet
 * @license http://www.gnu.org/licenses/gpl-3.0.txt GPLv3
 */

require_once (__DIR__).'/../lib/Object.php';

class MailHandler extends Object {
    public $to = null;
    public $from = null;
    public $subject = null;
    public $message = null;

    public function __construct() {
        //
    }

    public function send($html = true) {
        $headers = array(
            "MIME-Version: 1.0",
            "Content-type: text/". ($html ? "html" : "plain") ."; charset=iso-8859-1",
            "From: " .$this->from,
            "Reply-To: ". $this->from,
            "Subject: ". $this->subject,
        );

        if (mail($this->to, $this->subject, $this->message, implode("\r\n", $headers))) {
            $this->log('Mail send successful: '. $this->from .' -> '. $this->to . ' ('. $this->subject .')', 1);
            return true;
        }

        $this->log('Mail send failed: '. $this->from .' -> '. $this->to .' ('. $this->subject .')', 3);
        return false;
    }
}
?>
