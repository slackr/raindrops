<?php

require_once (__DIR__).'/../router/Router.php';

use \Raindrops\Router;

$route_exclusive = new Router();
$route_exclusive ->add_route(
    'destination1',
    $data = array(

    ),
    function ($data) {
        return array('destination' => true);
    }
);
$route_exclusive ->add_route(
    '!', // exclusive route, if return is non null, stop processing all other routes
    null,
    function () {
        return array('exclusive' => true);
    }
);
$view = $route_exclusive ->process();
assert('$view["exclusive"] == true', 'Exclusive should have stopped processing');

$route_default = new Router();
$route_default ->add_route(
    '!',
    $data = array(

    ),
    function ($data) {
        return null;
    }
);
$route_default ->add_route(
    'test',
    $data = array(

    ),
    function ($data) {
        return array('test' => true);
    }
);
$route_default ->add_route(
    '*', // default route
    null,
    function () {
        return array('default' => true);
    }
);
$view = $route_default->process();
assert('$view["default"] == true', 'Default route should have executed');

$_SERVER['REDIRECT_URL'] = '/test/';
$route_test = new Router();
$route_test ->add_route(
    '!',
    $data = array(

    ),
    function ($data) {
        return null;
    }
);
$route_test ->add_route(
    'test',
    $data = array(

    ),
    function ($data) {
        return array('test' => true);
    }
);
$route_test ->add_route(
    '*', // default route
    null,
    function () {
        return array('default' => true);
    }
);
$view = $route_test->process();
assert('$view["test"] == true', 'Test route did not execute');

echo "Tests completed \r\n";
var_dump($route_exclusive->log_tail());
var_dump($route_default->log_tail());
var_dump($route_test->log_tail());
?>
