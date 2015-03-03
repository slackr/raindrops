<?php namespace Raindrops;
/**
 * Raindrops Framework
 *
 * @author  Adrian@Slacknet
 * @license http://www.gnu.org/licenses/gpl-3.0.txt GPLv3
 */

require_once (__DIR__).'/../lib/Crypto.php';
require_once (__DIR__).'/../lib/AuthenticationConfig.php';
require_once (__DIR__).'/../controller/Authentication.php';
require_once (__DIR__).'/../controller/Identity.php';
require_once (__DIR__).'/../model/Database.php';

class Registration extends Identity {
    public $recovery_token = null;

    public function __construct(& $db, $identity, $realm, $id = 0) {
        $this->db = $db;
        $this->identity = $identity;
        $this->realm = $realm;
        $this->id = (int)$id;
    }

    public function create_identity($identity_data) {
        $timestamp = date(Config::DATE_FORMAT);

        if (! $this->is_email_valid($identity_data['email'])) {
            $this->log("Invalid email supplied for '". $this->identity_tostring() ."'", 3);
            return false;
        }

        if (! $this->sanity_check()) {
            $this->log("Sanity check failed for '". $this->identity_tostring() ."'", 3);
            return false;
        }

        if ($this->get_identity() == true) {
            if ($identity_data['recovery_token']) {
                $recovery_token = $identity_data['recovery_token'];
                $device = $identity_data['device'];

                if (! $this->is_device_valid($device)) {
                    $this->log("Invalid device supplied for '". $this->identity_tostring() ."'", 3);
                    return false;
                }

                $crypto = new Crypto();
                $auth = new Authentication($this->db, $this->identity, $this->realm);
                $crypto->generate_nonce($this->identity, array($recovery_token), false);

                $recovery_response = array(
                    'nonce' => $crypto->nonce,
                    'nonce_identity' => $this->identity,
                    'realm' => $this->realm,
                    'device' => $device,
                    'nonce_action' => 'recovery',
                );

                if ($auth->verify_challenge_response($recovery_response)) {
                    return $this->add_pubkey($device, $identity_data['pubkey']);
                } else {
                    $this->log("Auth log: ". json_encode($auth->log_tail()), 0);
                    $this->log("Crypto log: ". json_encode($crypto->log_tail()), 0);
                    $this->log("Identity recovery denied for '". $this->identity_tostring() ."', recovery token failed to verify", 3);
                    return false;
                }

            } else {
                $this->log("Identity '". $this->identity_tostring() ."' already exists and no recovery token was specified.", 3);
                return false;
            }
        }

        $this->email = $identity_data['email'];

        $query = "insert into ". AuthenticationConfig::DB_TABLE_IDENTITIES
                ." values (:id, :identity, :password, :email, :timestamp, :realm)";
        $params = array(
            ':id' => null,
            ':identity' => $this->identity,
            ':password' => null,
            ':email' => $this->email,
            ':timestamp' => $timestamp,
            ':realm' => $this->realm,
        );

        if ($this->db->query($query, $params)) {
            $this->log("Successfully created identity '". $this->identity_tostring() ."'", 1);

            if ($this->add_pubkey($identity_data['device'], $identity_data['pubkey'])) {
                return true;
            } else {
                $this->delete_identity(); // if add_pubkey failed during initial registration
                return false;
            }
        }
        $this->log("Failed to create identity '". $this->identity_tostring() ."'", 3);
        return false;
    }

    public function add_pubkey($device, $pubkey) {
        $timestamp = date(Config::DATE_FORMAT);

        if (! $this->is_device_valid($device)) {
            $this->log("Invalid device supplied for '". $this->identity_tostring() ."'", 3);
            return false;
        }

        $sfc = new Crypto();
        $pubkey = $sfc->fix_pem_format($pubkey);
        if (! $sfc->validate_key($pubkey)) {
            $this->log("Invalid pubkey supplied for '". $this->identity_tostring() ."' (PEM format only)", 3);
            return false;
        }

        if (! $this->id) {
            $this->get_identity();
        }

        $query = "insert into ". AuthenticationConfig::DB_TABLE_KEYS
                ." values (:id, :identity_id, :device, :pubkey, :timestamp)";

        $params = array(
            ':id' => null,
            ':identity_id' => $this->id,
            ':device' => $device,
            ':pubkey' => $pubkey,
            ':timestamp' => $timestamp,
        );

        if ($this->db->query($query, $params)) {
            $query = "delete from ". AuthenticationConfig::DB_TABLE_KEYS
                    ." where identity_id = :identity_id and device = :device and timestamp <> :timestamp";

            $params = array(
                ':identity_id' => $this->id,
                ':device' => $device,
                ':timestamp' => $timestamp,
            );
            if ($this->db->query($query, $params)) {
                $this->log("Successfully deleted old pubkeys for device: ". $device .", identity '". $this->identity_tostring() ."'", 1);
            } else {
                $this->log("Failed to delete old pubkeys for device: ". $device .", identity '". $this->identity_tostring() ."'", 2);
            }

            $this->log("Successfully added pubkey to identity '". $this->identity_tostring() ."'", 1);
            return true;
        }

        $this->log("Failed to add pubkey to identity '". $this->identity_tostring() ."'", 3);
        return false;
    }

    public function delete_identity() {
        if (! $this->id) {
            $this->get_identity();
        }

        $query = "delete from ". AuthenticationConfig::DB_TABLE_IDENTITIES ." where identity = :identity and realm = :realm";
        $params = array(
            ':identity' => $this->identity,
            ':realm' => $this->realm,
        );

        if ($this->db->query($query, $params, $limit = 1)) {
            $this->log("Successfully deleted identity '". $this->identity_tostring() ."'", 1);

            $query = "delete from ". AuthenticationConfig::DB_TABLE_KEYS ." where identity_id = :identity_id";
            $params = array(
                ':identity_id' => $this->id,
            );

            if ($this->db->query($query, $params)) {
                $this->log("Successfully deleted keys for '". $this->identity_tostring() ."'", 1);
            } else {
                $this->log("Identity was deleted but failed to delete keys for '". $this->identity_tostring() ."'", 2);
            }

            $this->id = 0; // zero out in case of object reuse
            return true;
        }

        $this->log("Failed to delete identity '". $this->identity_tostring() ."'", 3);
        return false;
    }

    public function generate_recovery_token($device, $email) {
        if (! $this->get_identity()) {
            $this->log("Identity does not exist: '". $this->identity_tostring() ."'", 3);
            return false;
        }

        if (! $this->is_device_valid($device)) {
            $this->log("Invalid device supplied for '". $this->identity_tostring() ."'", 3);
            return false;
        }

        if ($this->email !== $email) {
            $this->log("Identity email mismatch '". $email ."' != '". $this->email ."'", 3);
            return false;
        }

        $crypto = new Crypto();

        $this->recovery_token = $crypto->new_iv(4);
        //$this->log("Recovery token: '". $this->recovery_token ."'", 0);

        $auth = new Authentication($this->db, $this->identity, $this->realm);
        if ($auth->create_challenge($device, $action = 'recovery', array($this->recovery_token), $add_salt = false)) {
            $this->log("Successfully created recovery challenge for '". $this->identity_tostring() ."'", 1);
            return true;
        }

        $this->log("Failed to create recovery challenge for '". $this->identity_tostring() ."'", 3);
        return false;
    }

    public function is_email_valid($email) {
        return filter_var($email, FILTER_VALIDATE_EMAIL);
    }
    public function is_device_valid($device) {
        return preg_match(AuthenticationConfig::VALID_DEVICE_REGEX, $device);
    }
}
?>
