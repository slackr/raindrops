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
     * @var string this.generate_token() stores the result here
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
     * Create a challenge for the identity and store in database
     *
     * @see Authentication::$challenge
     *
     * @param array $seed (optional) Array to use as seed for nonce
     *
     * @return bool
     */
    public function create_challenge($seed = array()) {
        $crypto = new Crypto();
        $timestamp = date(Config::DATE_FORMAT);

        $crypto->generate_nonce($this->identity, $seed);

        $query = "insert into ". AuthenticationConfig::DB_TABLE_NONCE_HISTORY
                ." values (:id, :nonce, :nonce_identity, :timestamp, :realm)";
        $params = array(
            ':id' => null,
            ':nonce' => $crypto->nonce,
            ':nonce_identity' => $this->identity,
            ':timestamp' => $timestamp,
            ':realm' => $this->realm,
        );

        if ($this->db->query($query, $params)) {
            $this->log(
                "Successfully saved challenge for "
                ."'". $this->identity_tostring() ."', "
                ."nonce: '". $crypto->nonce ."', "
                ."timestamp: '". $timestamp ."'"
            , 1);

            $this->challenge = $crypto->nonce;
            return true;
        }

        $this->log("Failed to create challenge for '". $this->identity_tostring() ."'", 3);
        return false;
    }

    /**
     * Verify response to a challenge containing these parameters:
     *
     * nonce            => unique nonce that was signed
     * nonce_identity   => identity responsible for signing the nonce
     * realm            => the realm for the identity
     * nonce_signature  => base64 encoded signature of 'nonce' key
     *
     * Deletes challenge upon successful verification or if challenge has expired
     *
     * @param hash $response A response hash containing the data
     *
     * @return bool
     */
    public function verify_challenge_response($response) {
        $crypto = new Crypto();
        $valid = false;

        $query = "select * from ". AuthenticationConfig::DB_TABLE_NONCE_HISTORY
                ." where nonce = :nonce and nonce_identity = :nonce_identity and realm = :realm"
                ." order by id desc";

        $params = array(
            ':nonce' => $response['nonce'],
            ':nonce_identity' => $response['nonce_identity'],
            ':realm' => $response['realm'],
        );

        $this->db->query($query, $params, $limit = 1);
        $row = $this->db->fetch();

        if (isset($row['id'])) {
            $timeframe = time() - AuthenticationConfig::NONCE_TIMEFRAME;
            $nonce_timestamp = strtotime($row['timestamp']);

            if ($nonce_timestamp >= $timeframe) {
                $this->log("Found nonce for '". $response['nonce_identity'] ."@". $response['realm'] ."' within acceptable timeframe, nonce: '". $response['nonce'] ."'", 1);

                if ($crypto->verify_signature($response['nonce'], $response['nonce_signature'], $this->pubkey)) {
                    $valid = true;
                    $this->log("Authentication for '". $response['nonce_identity'] ."@". $response['realm'] ."' successful. Nonce signature was valid.", 1);

                    $this->delete_challenge($row['id']);
                } else {
                    $this->log(
                        "Nonce signature was invalid for '". $response['nonce'] ."',"
                        ." identity: '". $response['nonce_identity'] ."@". $response['realm'] ."'"
                        ." crypto-log: '". join("\n", $crypto->log_tail()) ."'"
                    , 3);
                }
            } else {
                $this->log("Time expired for nonce: '". $response['nonce'] ."', identity: '". $response['nonce_identity'] ."@". $response['realm'] ."'", 1);

                $this->delete_challenge($row['id']);
            }
        } else {
            $this->log("No nonce found for identity: '". $response['nonce_identity'] ."@". $response['realm'] ."' within acceptable timeframe", 1);
        }

        return $valid;
    }

    /**
     * Removes a challenge from the database
     *
     * @param integer $id Challenge index in db
     *
     * @return bool
     */
    public function delete_challenge($id) {
        $query = "delete from ". AuthenticationConfig::DB_TABLE_NONCE_HISTORY . " where id = :id";
        $params = array(
            ':id' => $id,
        );

        if ($this->db->query($query, $params, $limit = 1)) {
            $this->log("Successfully deleted challenge with id: '". $id ."'", 1);
            return true;
        }

        $this->log("Failed to delete challenge with id: '". $id ."'", 3);
        return false;
    }

    /**
     * Generates a token containing a timed value
     * It will be joined by a TOKEN_SEPARATOR
     *
     * Tokens:
     * timestamp => this will be used for timed verification, should be first
     * ip => ip of client, something the client cannot forge easily
     *
     * @see Authentication::$token
     *
     * @return void
     */
    public function generate_auth_token() {
        $seed = array(
            time(),
            $_SERVER['REMOTE_ADDR'],
        );

        $this->token = join(AuthenticationConfig::TOKEN_SEPARATOR, $seed);
        $this->log("New token generated: '". $this->token ."'", 1);
    }

    /**
     * A string token separated by TOKEN_SEPARATOR
     *
     * @see Authentication::generate_token()
     *
     * @param string $token Token containing a timestamp and any other validation data
     *
     * @return bool
     */
    public function verify_auth_token($token) {
        $pieces = explode(AuthenticationConfig::TOKEN_SEPARATOR, $token);
        $timestamp = (int)$pieces[0];
        array_shift($pieces);
        $token_data = join(AuthenticationConfig::TOKEN_SEPARATOR, $pieces);

        if ($timestamp == 0) {
            $this->log("Invalid timestamp in token: '". $token ."' (timestamp: '". $timestamp ."')", 3);
            return false;
        }
        if ((time() - $timestamp) > Config::TOKEN_TIMEFRAME) {
            $this->log("Token has expired: '". $token ."'", 3);
            return false;
        }

        $this->generate_auth_token();

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
