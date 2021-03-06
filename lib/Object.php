<?php namespace Raindrops;
/**
 * Raindrops Framework
 *
 * @author  Adrian@Slacknet
 * @license http://www.gnu.org/licenses/gpl-3.0.txt GPLv3
 */

require_once (__DIR__).'/Config.php';

class Object {
    const LOG_DEBUG = 0;
    const LOG_INFO = 1;
    const LOG_WARN = 2;
    const LOG_ERROR = 3;

    public $db = null;

    public $log_name = null;

    protected $log_levels = array(
        Object::LOG_DEBUG => 'debug',
        Object::LOG_INFO => 'info',
        Object::LOG_WARN => 'warn',
        Object::LOG_ERROR => 'error',
    );
    protected $log_entries = array();

    public function log($msg, $level = Object::LOG_INFO, $custom_error_code = null) {
        $entry = null;

        if ($level >= Config::LOG_LEVEL) {
            $entry = date(Config::LOG_DATE_FORMAT) .' - '
                    . strtoupper($this->log_levels[$level]) . ($this->log_name ? '(' . $this->log_name . '): ' : ': ')
                    . $msg;

            $this->log_entries[] = $entry;

            if ($level >= Object::LOG_ERROR && Config::THROW_EXCEPTIONS == true) {
                throw new \Exception($msg, $custom_error_code);
            }
        }
    }

    public function log_tail($number = 50) {
        return array_slice($this->log_entries, $number * -1);
    }

    /**
     * echo gettok("one two three",2," "); // prints 'two'
     */
    public function gettok($string,$num,$delim = " ") {
        $x = explode($delim,$string);
        return $x[$num-1];
    }


    /**
     * removes port numbers from XFF header
     *
     * 127.0.0.1, 127.0.0.2:1234 -> 127.0.0.1, 127.0.0.2
     * 127.0.0.1:1234 -> 127.0.0.0.1
     */
    public function clean_xff_header($xff) {
        $hosts = explode(',', $xff);
        $a = [];

        for ($h = 0; $h < sizeof($hosts); $h++) {
            $a = explode(':', $hosts[$h]);
            $hosts[$h] = $a[0];
        }

        $clean_xff = implode(',', $hosts);

        $this->log("XFF clean: '". $xff ."' -> '". $clean_xff ."'", 0);
        return $clean_xff;
    }

}
?>
