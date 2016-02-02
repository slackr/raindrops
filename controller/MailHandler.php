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
    public $from_name = null;
    public $subject = null;
    public $message = null;

    public function __construct() {
        //
    }

    public function send($html = true) {

        if (strlen(Config::SENDGRID_API_KEY) > 0) {
            $url = Config::SENDGRID_API_URL; //'https://api.sendgrid.com/';
            $sendgrid_apikey = Config::SENDGRID_API_KEY;

            $params = array(
                'to'        => $this->to,
                'from'      => $this->from,
                'fromname'  => $this->from_name,
                'subject'   => $this->subject,
                'text'      => $this->message,
              );

            $request =  $url . 'api/mail.send.json';

            // Generate curl request
            $curl_session = curl_init($request);
            curl_setopt($curl_session, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
            curl_setopt($curl_session, CURLOPT_HTTPHEADER, array('Authorization: Bearer ' . $sendgrid_apikey));
            // Tell curl to use HTTP POST
            curl_setopt ($curl_session, CURLOPT_POST, true);
            // Tell curl that this is the body of the POST
            curl_setopt ($curl_session, CURLOPT_POSTFIELDS, $params);
            // Tell curl not to return headers, but do return the response
            curl_setopt($curl_session, CURLOPT_HEADER, false);
            curl_setopt($curl_session, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($curl_session, CURLOPT_SSL_VERIFYHOST, 0);
            curl_setopt($curl_session, CURLOPT_SSL_VERIFYPEER, 0);

            // obtain response
            curl_exec($curl_session);
            $http_code = curl_getinfo($curl_session, CURLINFO_HTTP_CODE);
            if ($http_code != 200) {
                $response_error = curl_error($curl_session);
            }
            curl_close($curl_session);

            // print everything out
            if ($http_code != 200) {
                $this->log('Mail send (SendGrid) failed: ' . $http_code . ' - ' . json_encode($response_error), 3);
                return false;
            } else {
                $this->log('Mail send (SendGrid) success: ' . json_encode($http_code) . ' - ' . $this->from .' -> '. $this->to . ' ('. $this->subject .')', 1);
                return true;
            }


        } else {

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
        }


        $this->log('Mail send failed: '. $this->from .' -> '. $this->to .' ('. $this->subject .')', 3);
        return false;
    }
}
?>
