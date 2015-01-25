<?php namespace Raindrops;
/**
 * Raindrops Framework
 *
 * @author  Adrian@Slacknet
 * @license http://www.gnu.org/licenses/gpl-3.0.txt GPLv3
 */

require_once (__DIR__).'/../lib/Object.php';
require_once (__DIR__).'/../controller/Authentication.php';
require_once (__DIR__).'/../controller/Identity.php';

class SessionHandler extends Object {
    public $id = null;
    public $realm = null;
    public $session_id = null;
    public $session_ip = null;

    public function __construct(& $db, $realm = null, $session_id = null, $session_ip = null) {
        $this->db = $db;
        $this->realm = $realm;
        $this->session_id = $session_id;
        $this->session_ip = $session_ip;
    }

    public function verify() {
        $seed = array($this->session_ip);

        $this->id = null;

        if ($this->session_id != null) {
            session_id($this->session_id);
        }

        if (isset($_SESSION['rd_auth_identity'])) {
            $auth = new \Raindrops\Authentication($this->db, $_SESSION['rd_auth_identity'], $this->realm);
            if ($auth->verify_auth_token($_SESSION['rd_auth_token'], $seed)) {
                $_SESSION['rd_auth_token'] = $auth->token; // update token to renew timestamp

				$this->id = new \Raindrops\Identity($this->db, $_SESSION['rd_auth_identity'], $this->realm);
				if (! $this->id->get_identity()) {
					$this->log('Failed to retrieve identity data: '. join('',$this->id->log_tail(1)), 3);
                    return false;
				}
            } else {
				$this->id = null;
                session_destroy();
                session_start();

                $this->log('Token verification failed: '. join('',$auth->log_tail(1)), 3);
                return false;
            }
        }

        $this->log('Session is valid', 0);
        return true;
    }
}
?>
