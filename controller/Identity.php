<?php namespace Raindrops;
/**
 * Raindrops Framework
 *
 * @author  Adrian@Slacknet
 * @license http://www.gnu.org/licenses/gpl-3.0.txt GPLv3
 */

require_once (__DIR__).'/../lib/Object.php';
require_once (__DIR__).'/../lib/Crypto.php';
require_once (__DIR__).'/../lib/AuthenticationConfig.php';

class Identity extends Object {
    public $id = null;
    public $realm = null;
    public $email = null;
    public $identity = null;
    public $pubkeys = null;

    public function __construct(& $db, $identity, $realm, $id = 0) {
        $this->db = $db;
        $this->identity = $identity;
        $this->realm = $realm;
        $this->id = (int)$id;
    }

    public function identity_tostring() {
        return "(n:". $this->identity .",r:". $this->realm .",i:". $this->id .")";
    }

    public function get_identity() {
        if (! $this->sanity_check()) {
            $this->log("Identity or realm input invalid for '". $this->identity_tostring() ."'. Will not attempt data retrieval.", 3);
            return false;
        }

        $query = "select * from ". AuthenticationConfig::DB_TABLE_IDENTITIES;

        if ((int)$this->id > 0) {
            $query .= " where id = :id";
            $params = array(
                ':id' => $this->id,
            );
        } else {
            $query .= " where identity = :identity and realm = :realm";
            $params = array(
                ':identity' => $this->identity,
                ':realm' => $this->realm,
            );
        }


        $this->db->query($query, $params, $limit = 1);
        $row = $this->db->fetch();
        if (isset($row['identity'])) {
            $this->pubkeys = array();

            $query_keys = "select * from ". AuthenticationConfig::DB_TABLE_KEYS;
            $query_keys .= " where identity_id = :identity_id order by id desc";
            $params_keys = array(
                ':identity_id' => $row['id'],
            );

            if ($this->db->query($query_keys, $params_keys)) {
                while ($row_keys = $this->db->fetch()) {
                    $this->pubkeys[$row_keys['device']] = $row_keys['pubkey'];
                }
            } else {
                $this->log("Failed to retrieve keys for '". $this->identity_tostring() ."'", 3);
                return false;
            }

            $this->identity = $row['identity'];
            $this->realm = $row['realm'];
            $this->email = $row['email'];
            $this->id = (int)$row['id'];

            $this->log("Identity data for '". $this->identity_tostring() ."' retrieved, " . sizeof($this->pubkeys) . " keys found", 1);
            return true;
        }

        $this->log("Identity data for '". $this->identity_tostring() ."' not found", 2); // should not error out
        return false;
    }

    public function sanity_check() {
        if ((int)$this->id > 0) {
            $this->log("Identity input passed sanity check: 'valid int: ". $this->id ."'", 1);
            return true;
        }

        $valid_realm = false;
        $valid_identity = false;

        if (preg_match(AuthenticationConfig::VALID_IDENTITY_REGEX, $this->identity)) {
            $this->log("Identity input passed sanity check: '". $this->identity ."'", 1);
            $valid_identity = true;
        } else {
            $this->log("Identity input sanity check failed: '". $this->identity ."'", 3);
        }
        if (preg_match(AuthenticationConfig::VALID_REALM_REGEX, $this->realm)) {
            $this->log("Realm input passed sanity check: '". $this->realm ."'", 1);
            $valid_realm = true;
        } else {
            $this->log("Realm input sanity check failed: '". $this->realm ."'", 3);
        }

        return $valid_identity && $valid_realm;
    }
}

?>
