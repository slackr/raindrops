<?php namespace Raindrops;
/**
 * Raindrops Framework
 *
 * @author  Adrian@Slacknet
 * @license http://www.gnu.org/licenses/gpl-3.0.txt GPLv3
 */

require_once (__DIR__).'/../lib/Config.php';
require_once (__DIR__).'/../lib/Object.php';

use PDO;
use PDOException;

class Database extends Object {

    private $dsn = '';

    private $username = DatabaseConfig::DB_USER;
    private $password = DatabaseConfig::DB_PASS;
    private $db_name = DatabaseConfig::DB_NAME;
    private $db_host = DatabaseConfig::DB_HOST;
    private $db_port = DatabaseConfig::DB_PORT;

    private $options = array();
    private $fetch_style = PDO::FETCH_ASSOC;
    private $sth = null;
    private $dbh = null;
    private $pdo_driver = 'mysql';

    public $query = '';
    public $connected = false;
    public $rows_affected = 0;

    public function __construct($pdo_driver = 'mysql') {
        $this->pdo_driver = $pdo_driver;
    }

    public function query($query, $params = array(), $limit = null) {
        if ($limit != null) {
            switch ($this->pdo_driver) {
                case 'sqlsrv':
                    $query = preg_replace('/^(select|delete|update)\s+/si','$1 top('. $limit .') ', $query);
                break;
                default: // mysql
                    $query .= " limit $limit";
                break;
            }
        }

        $this->sth = $this->dbh->prepare($query);
        if (!$this->sth) {
            $this->log("Error preparing query(): ". $this->sql_error_info($this->dbh, $query), 3);
            return false;
        }

        $this->rows_affected = 0;
        $this->query = $this->sth->queryString;

        if (sizeof($params) > 0) {
            $this->query .= ' (Parameters: '. json_encode($params) .')';
        }

        $ret = $this->sth->execute($params);
        if ($ret) {
            $this->rows_affected = $this->sth->rowCount();
            $this->log('Query executed: '. $this->query .' (affected: '. $this->rows_affected .')', 0);
            return true;
        }

        $this->log("Error executing query(): ". $this->sql_error_info($this->sth, $this->query), 3);
        return false;
    }

    public function count($table, $params = array()) {
        $this->query("select count(*) as num from " . $table, $params);

        $ret = $this->sth->fetch();
        return ($ret['num'] ? $ret['num'] : '0');
    }

    public function delete($table, $params = array(), $limit = null) {
        $ret = $this->query("delete from " . $table, $params, $limit);

        return $ret;
    }

    public function fetch($query_ret = true) {
        if ($query_ret) {
            $ret = $this->sth->fetch($this->fetch_style);
            return $ret;
        }

        return $query_ret;
    }

    public function fetch_all() {
        $ret = $this->sth->fetchAll($this->fetch_style);
        return $ret;
    }

    public function connect() {
        $driver_options = array();
        $driver_dsn = '';
        switch ($this->pdo_driver) {
            case 'mysql':
                $driver_options = array(
                    PDO::MYSQL_ATTR_INIT_COMMAND => 'SET NAMES utf8',
                );
                $driver_dsn = 'mysql:host='.$this->db_host.''.($this->db_port ? ';port='.$this->db_port : '').';dbname='.$this->db_name;
            break;
            case 'sqlsrv':
                $driver_dsn = 'sqlsrv:server='.$this->db_host.''.($this->db_port ? ','.$this->db_port : '').';database='.$this->db_name;
            break;
        }
        $this->options = $driver_options;
        $this->dsn = $driver_dsn;

        try {
            $this->dbh = new PDO($this->dsn, $this->username, $this->password, $this->options);
            if ($this->dbh) {
                $this->log("Database DSN: ".$this->dsn, 0);
                $this->log("Successfully connected to database", 1);
                $this->connected = true;
            }
        }
        catch (PDOException $e) {
            $this->log("Error connecting to database: ". $e->getMessage(), 3);
            $this->connected = false;
        }

        return $this->connected;
    }

    private function sql_error_info(& $obj, $query = '') {
        $err = $obj->errorInfo();
        return "DB ERROR(" . $err[0] . ")" . (Config::DEBUG ? " - ".$err[2]." - QUERY: ". $query : "");
    }
}

?>
