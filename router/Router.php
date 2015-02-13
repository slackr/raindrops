<?php namespace Raindrops;
/**
 * Raindrops Framework
 *
 * @author  Adrian@Slacknet
 * @license http://www.gnu.org/licenses/gpl-3.0.txt GPLv3
 */

require_once (__DIR__).'/../lib/Object.php';

class Router extends Object {
    public $request_action = null;
    public $routes = array();

    public function __construct() {
        if (! isset($_SERVER['REDIRECT_URL'])) {
            $_SERVER['REDIRECT_URL'] = $_SERVER['REQUEST_URI'];
        }

        $get = explode('/', substr($_SERVER['REDIRECT_URL'], 1));
        $this->request_action = preg_replace('/[^a-z0-9\_\-]+/i', '', $get[0]);

        $this->log("Request action parsed: '". $this->request_action ."'", 1);
    }

    public function add_route($destination, $data = array(), $callback) {
        $destination = preg_replace('/[^a-z0-9\_\-\*\!]+/i', '', $destination);
        $this->routes[$destination] = array(
            'data' => $data,
            'callback' => $callback,
        );

        $this->log("Added route '". $destination ."'", 1);
    }

    public function process() {
        $matched_route = false;
        $view = null;

        if (isset($this->routes['!'])) {
            $view = $this->routes['!']['callback']($this->routes['!']['data']);
            if ($view != null) {
                $this->log("Exclusive route (!) returned non-null value. Processing stopped", 1);

                return $view;
            } // stop processing and return view
        }

        foreach ($this->routes as $destination => $process) {
            if ($destination === $this->request_action) {
                $view = $process['callback']($process['data']);
                $matched_route = true;

                $this->log("Route '". $destination . "' matched to request action.", 1);
            }
        }

        if (! $matched_route) {
            $this->log("No route matched to request action '". $this->request_action . "'", 1);

            if (isset($this->routes['*'])) {
                $view = $this->routes['*']['callback']($this->routes['*']['data']);

                $this->log("Default route found and processed", 1);
            }
        }

        return $view;
    }
}
?>
