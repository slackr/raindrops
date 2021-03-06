<?php namespace Raindrops;
/**
 * Raindrops Framework
 *
 * @author  Adrian@Slacknet
 * @license http://www.gnu.org/licenses/gpl-3.0.txt GPLv3
 */

require_once (__DIR__).'/../lib/Crypto.php';
require_once (__DIR__).'/../lib/AuthenticationConfig.php';
require_once (__DIR__).'/../controller/Identity.php';

/**
 * Provides authentication capabilities
 *
 */
class Authentication extends Identity {
    /**
     * @var string this.create_challenge() stores the result here
     */
    public $challenge = null;

    /**
     * @var string this.generate_auth_token() stores the result here
     */
    public $token = null;

    /**
     * Sets up database, and any ID info passed through
     *
     * @param object $db        Reference to db object
     * @param string $identity  Nickname of identity
     * @param string $realm     Which realm to use
     * @param integer    $id       (optional) Identity index in db
     */
    public function __construct(& $db, $identity, $realm, $id = 0) {
        $this->db = $db;
        $this->identity = $identity;
        $this->realm = $realm;
        $this->id = $id;
    }

    /**
     * Create a challenge for the identity and store in database.
     *
     * A device name must be specified to tie the challenge to a pubkey for the identity
     *
     * @see Authentication::$challenge
     *
     * @param string $device Which device to associate challenge with
     * @param string $action Which action to associate challenge with
     * @param array $seed (optional) Array to use as seed for nonce
     * @param bool $add_salt (optional) Add salt to nonce?
     *
     * @return bool
     */
    public function create_challenge($device, $action = 'auth', $seed = array(), $add_salt = true) {
        if ($action == 'auth'
            && ! isset($this->pubkeys[$device])) {
            $this->log("No pubkey associated with device: '" . $device . "' for '". $this->identity_tostring() ."'", 3);
            return false;
        }

        $crypto = new Crypto();
        $timestamp = date(Config::DATE_FORMAT);

        $crypto->generate_nonce($this->identity, $seed, $add_salt);

        $query = "insert into ". AuthenticationConfig::DB_TABLE_NONCE_HISTORY
                ." values (:id, :nonce, :nonce_identity, :timestamp, :realm, :device, :nonce_action)";
        $params = array(
            ':id' => null,
            ':nonce' => $crypto->nonce,
            ':nonce_identity' => $this->identity,
            ':timestamp' => $timestamp,
            ':realm' => $this->realm,
            ':device' => $device,
            ':nonce_action' => $action,
        );

        if ($this->db->query($query, $params)) {
            $this->log(
                "Successfully saved '". $action ."' challenge for '". $this->identity_tostring() ."', "
                ."nonce: '". $crypto->nonce ."', "
                ."timestamp: '". $timestamp ."', "
                ."device: '". $device ."'"
            , 1);

            $this->challenge = $crypto->nonce;
            return true;
        }

        $this->log("Failed to create '". $action ."' challenge for '". $this->identity_tostring() ."'", 3);
        return false;
    }

    /**
     * Verify response to a challenge containing these parameters:
     *
     * nonce            => unique string that was signed
     * nonce_identity   => identity responsible for signing the nonce
     * realm            => the realm for the identity
     * device           => the device to associate nonce with
     * nonce_signature  => base64 encoded signature of 'nonce' key
     * nonce_action     => (optional) challenge action if not 'auth'
     *
     * Deletes challenge upon successful verification or if challenge has expired
     *
     * @param hash $response A response hash containing the data
     *
     * @return bool
     */
    public function verify_challenge_response($response) {
        if (! isset($response['nonce_action'])) {
            $response['nonce_action'] = 'auth';
        }

        if ($response['nonce_action'] == 'auth'
            && ! isset($this->pubkeys[$response['device']])) {
            $this->log("No pubkey associated with device: '" . $response['device'] . "' for '". $this->identity_tostring() ."'", 3);
            return false;
        }

        $pubkey = $this->pubkeys[$response['device']];

        $crypto = new Crypto();
        $valid = false;

        $query = "select * from ". AuthenticationConfig::DB_TABLE_NONCE_HISTORY
                ." where nonce = :nonce and nonce_identity = :nonce_identity and realm = :realm and device = :device and nonce_action = :nonce_action"
                ." order by id desc";

        $params = array(
            ':nonce' => $response['nonce'],
            ':nonce_identity' => $response['nonce_identity'],
            ':realm' => $response['realm'],
            ':device' => $response['device'],
            ':nonce_action' => $response['nonce_action'],
        );

        $this->db->query($query, $params, $limit = 1);
        $row = $this->db->fetch();

        if (isset($row['id'])) {
            $timeframe = time() - AuthenticationConfig::NONCE_TIMEFRAME;
            $nonce_timestamp = strtotime($row['timestamp']);

            if ($nonce_timestamp >= $timeframe) {
                $this->log("Found '". $response['nonce_action'] ."' nonce for device: '". $response['device'] ."', '". $response['nonce_identity'] ."@". $response['realm'] ."' within acceptable timeframe, nonce: '". $response['nonce'] ."'", 1);

                $valid = true;
                if ($response['nonce_action'] == 'auth') {
                    if ($crypto->verify_signature($response['nonce'], $response['nonce_signature'], $pubkey)) {
                        $this->log("Authentication for device: '". $response['device'] ."', '". $response['nonce_identity'] ."@". $response['realm'] ."' successful. Nonce signature is valid for '". $response['nonce_action'] ."'", 1);

                        $this->delete_challenges($response);
                    } else {
                        $valid = false;
                        $this->log("Crypto-log: ". json_encode($crypto->log_tail()), 0);
                        $this->log("Nonce signature is invalid for '". $response['nonce'] ."', identity: '". $response['nonce_identity'] ."@". $response['realm'] ."'", 3);
                    }
                } else {
                    $this->delete_challenges($response);
                }
            } else {
                $this->log("Time expired for '". $response['nonce_action'] ."' nonce: '". $response['nonce'] ."', device: '". $response['device'] ."', identity: '". $response['nonce_identity'] ."@". $response['realm'] ."'", 1);

                $this->delete_challenges($response);
            }
        } else {
            $this->log("No '". $response['nonce_action'] ."' nonce found for identity: '". $response['nonce_identity'] ."@". $response['realm'] ."', device: '". $response['device'] ."', within acceptable timeframe", 1);
        }

        return $valid;
    }

    /**
     * Removes a challenge from the database
     *
     * @param integer $
     *
     * @return bool
     */
    public function delete_challenges($challenge) {
        $query = "delete from ". AuthenticationConfig::DB_TABLE_NONCE_HISTORY
                . " where   nonce_identity = :nonce_identity"
                . " and     device = :device"
                . " and     realm = :realm"
                . " and     nonce_action = :nonce_action";

        $params = array(
            ':nonce_identity' => $challenge['nonce_identity'],
            ':realm' => $challenge['realm'],
            ':device' => $challenge['device'],
            ':nonce_action' => $challenge['nonce_action'],
        );

        if ($this->db->query($query, $params)) {
            $this->log("Successfully deleted all '". $challenge['nonce_action'] ."' challenges for '" . $this->identity_tostring() . "', device: " . $challenge['device'], 1);
            return true;
        }

        $this->log("Failed to delete '". $challenge['nonce_action'] ."' challenges for '" . $this->identity_tostring() . "', device: " . $challenge['device'], 3);
        return false;
    }

    /**
     * Generates a token containing a timed value
     * It will be joined by a TOKEN_SEPARATOR
     *
     * Token contain:
     * timestamp => this will be used for timed verification, should be first
     * ip => ip of client, something the client cannot forge easily
     *
     * @see Authentication::$token
     *
     * @param array $seed An array to seed into new token ($_SERVER['REMOVE_ADDR'] for example)
     *
     * @return void
     */
    public function generate_auth_token($seed) {
        array_unshift($seed, time());

        $this->token = join(AuthenticationConfig::TOKEN_SEPARATOR, $seed);
        $this->log("New token generated: '". $this->token ."'", 1);
    }

    /****
     * A string token separated by TOKEN_SEPARATOR
     *
     * @see Authentication::generate_auth_token()
     *
     * @param string $token Token containing a timestamp and any other validation data
     * @param array $seed An array to seed into new token ($_SERVER['REMOVE_ADDR'] for example)
     *
     * @return bool
     */
    public function verify_auth_token($token, $seed) {
        $pieces = explode(AuthenticationConfig::TOKEN_SEPARATOR, $token);
        $timestamp = (int)$pieces[0];
        array_shift($pieces);
        $token_data = join(AuthenticationConfig::TOKEN_SEPARATOR, $pieces);

        if ($timestamp == 0) {
            $this->log("Invalid timestamp in token: '". $token ."' (timestamp: '". $timestamp ."')", 3);
            return false;
        }

        $this->log('Token age: '. (time() - $timestamp), 0);

        if ((time() - $timestamp) > Config::TOKEN_TIMEFRAME) {
            $this->log("Token has expired: '". $token ."'", 3);
            return false;
        }

        $this->generate_auth_token($seed);

        $new_pieces = explode(AuthenticationConfig::TOKEN_SEPARATOR, $this->token);
        array_shift($new_pieces);
        $new_token_data = join(AuthenticationConfig::TOKEN_SEPARATOR, $new_pieces);

        if ($new_token_data !== $token_data) {
            $this->log("Token data is invalid: '". $token ."' != '". $this->token ."'", 3);
            $this->token = null;
            return false;
        }

        $this->log("Token '". $token ."' is valid. Updated token available.", 1);
        return true;
    }
}
?>
