<?php namespace Raindrops;
/**
 * Raindrops Framework
 *
 * @author  Adrian@Slacknet
 * @license http://www.gnu.org/licenses/gpl-3.0.txt GPLv3
 */

class AuthenticationConfig {
    const DB_TABLE_NONCE_HISTORY = 'rd_nonce_history';
    const DB_TABLE_IDENTITIES = 'rd_identities';
    const DB_TABLE_KEYS = 'rd_keys';

    const NONCE_TIMEFRAME = 300; // in seconds

    const VALID_IDENTITY_REGEX = '/^[a-z0-9\s]{1,32}$/si';
    const VALID_REALM_REGEX = '/^[a-z0-9\s]{1,64}$/si';
    const VALID_DEVICE_REGEX = '/^[a-z0-9\s]{1,32}$/si';

    const TOKEN_SEPARATOR = '|';
}
?>
