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
    public $identity = null;
    public $session_id = null;
    public $session_seed = null;

    private $previous_session_id = null;

    public function __construct(& $db, $realm = null, $session_id = null, $session_seed = null, $identity = null) {
        $this->db = $db;
        $this->realm = $realm;
        $this->session_id = $session_id;
        $this->session_seed = $session_seed;
        $this->identity = ($identity ? $identity : $_SESSION['rd_auth_identity']);
    }

    public function verify($read_only = false) {
        $seed = array($this->session_seed);
        $is_ro = ($read_only ? '(read_only) ' : '');

        $this->id = null;

        if ($this->session_id != null) {
            if ($this->session_sanity_check()) {
                $this->hijack_session($this->session_id);
            } else {
                $this->log('Invalid session id '. $this->session_tostring(), 3);
                return false;
            }
        }

        if (isset($_SESSION['rd_auth_identity'])) {
            if (strtolower($_SESSION['rd_auth_identity']) === strtolower($this->identity)) {
                $auth = new \Raindrops\Authentication($this->db, $_SESSION['rd_auth_identity'], $this->realm);
                if ($auth->verify_auth_token($_SESSION['rd_auth_token'], $seed)) {
                    if (! $read_only) {
                        $_SESSION['rd_auth_token'] = $auth->token; // update token to renew timestamp

                        $this->id = new \Raindrops\Identity($this->db, $_SESSION['rd_auth_identity'], $this->realm);
                        if (! $this->id->get_identity()) {
                            $this->log('Failed to retrieve identity data '. $this->session_tostring() .': '. json_encode($this->id->log_tail(1)), 3);
                            $this->id = null;
                            return false;
                        }
                    }

                    $this->restore_previous_session();

                    $this->log($is_ro .'Session is valid '. $this->session_tostring() .' ('. json_encode($auth->log_tail(5)) .')', 1);
                    return true;
                } else {
                    $this->restore_previous_session();

                    $this->id = null;
                    if (! $read_only) {
                        $this->destroy();
                    }

                    $this->log($is_ro . 'Token verification failed '. $this->session_tostring() .': '. json_encode($auth->log_tail(1)), 3);
                    return false;
                }
            } else {
                $this->log($is_ro ."Session identity does not match input: '". $this->identity ."' != '". $_SESSION['rd_auth_identity'] ."'", 3);
            }
        }

        $this->restore_previous_session();
        $this->log($is_ro . 'Session is invalid '. $this->session_tostring(), 3);
        return false;
    }

    public function logout() {
        $this->destroy();
    }
    public function destroy() {
        session_destroy();
        session_commit();
        session_start();
        $this->log('Session '. $this->session_id .' destroyed', 1);
    }

    public function hijack_session($session_id) {
        $this->log('Hijacking session: '. $session_id, 0);
        $this->previous_session_id = session_id();
        $this->swap_session($session_id);
    }

    public function restore_previous_session() {
        if ($this->previous_session_id) {
            $this->log('Restoring to previous session: '. $this->previous_session_id, 0);
            $this->swap_session($this->previous_session_id);
        } else {
            $this->log('No previous session to restore', 0);
        }
    }

    public function swap_session($session_id) {
        session_commit();
        session_id($session_id);
        session_start();

        $this->log('Session swapped to: '. session_id(), 0);
    }

    public function session_sanity_check() {
        return preg_match('/^[a-z0-9]{26}$/i', $this->session_id);
    }

    public function session_tostring() {
        return "(sid:". $this->session_id .",ip:". $this->session_seed .")";
    }
}
?>
