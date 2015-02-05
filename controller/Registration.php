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

        if ($this->get_identity() == true) {
            $this->log("Identity '". $this->identity_tostring() ."' already exists", 3);
            return false;
        }

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

            $this->id = 0; // zero out in case of object reuse

            if ($this->db->query($query, $params)) {

                $this->log("Successfully deleted keys for '". $this->identity_tostring() ."'", 1);
                return true;
            } else {
                $this->log("Identity was deleted but failed to delete keys for '". $this->identity_tostring() ."'", 3);
                return false;
            }
        }

        $this->log("Failed to delete identity '". $this->identity_tostring() ."'", 3);
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
