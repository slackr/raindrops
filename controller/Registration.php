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

    public function __construct(& $db, $identity, $realm) {
        $this->db = $db;
        $this->identity = $identity;
        $this->realm = $realm;
        $this->id = 0;
    }

    public function create_identity($identity_data) {
        $timestamp = date(Config::DATE_FORMAT);

        $sfc = new Crypto();

        $identity_data['pubkey'] = $sfc->fix_pem_format($identity_data['pubkey']);
        if (! $sfc->validate_key($identity_data['pubkey'])) {
            $this->log("Invalid pubkey supplied for '". $this->identity_tostring() ."' (PEM format only)", 3);
            return false;
        }

        if ($this->get_identity() == true) {
            $this->log("Identity '". $this->identity_tostring() ."' already exists", 3);
            return false;
        }

        $query = "insert into ". AuthenticationConfig::DB_TABLE_IDENTITIES
                ." values (:id, :identity, :password, :pubkey, :timestamp, :realm)";
        $params = array(
            ':id' => null,
            ':identity' => $this->identity,
            ':password' => null,
            ':pubkey' => $identity_data['pubkey'],
            ':timestamp' => $timestamp,
            ':realm' => $this->realm,
        );

        if ($this->db->query($query, $params)) {
            $this->pubkey = $identity_data['pubkey'];
            $this->log("Successfully created identity '". $this->identity_tostring() ."'", 1);
            return true;
        }

        $this->log("Failed to create identity '". $this->identity_tostring() ."'", 3);
        return false;
    }

    public function delete_identity() {
        $query = "delete from ". AuthenticationConfig::DB_TABLE_IDENTITIES ." where identity = :identity and realm = :realm";
        $params = array(
            ':identity' => $this->identity,
            ':realm' => $this->realm,
        );

        if ($this->db->query($query, $params, $limit = 1)) {
            $this->log("Successfully deleted identity '". $this->identity_tostring() ."'", 1);
            return true;
        }

        $this->log("Failed to delete identity '". $this->identity_tostring() ."'", 3);
        return false;
    }
}
?>
