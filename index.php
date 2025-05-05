<?php
declare(strict_types=1);

require_once "controllers/students_controller.php";
require_once "error_handler.php";
require_once "database/database.php";
require_once "gateways/students_gateway.php";
require_once "controllers/auth_controller.php";
require_once "gateways/auth_gateway.php";
require_once "controllers/auth.php";
require_once "controllers/jwt_controller.php";

set_error_handler("ErrorHandler::handleError");
set_exception_handler("ErrorHandler::handleException");

header("Access-Control-Allow-Origin: http://localhost:63342");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$method = $_SERVER['REQUEST_METHOD'];
$segments = explode('/', trim($uri, '/'));
$page = isset($_GET['page']) ? (int)$_GET['page'] : 1;

$jwtController = new JwtController();

$database = new Database();

$AuthGateway = new AuthGateway($database);

if ($segments[0] === 'students') {
    $auth = new Auth($jwtController, $AuthGateway);
    if (!$auth->authenticate()) {
        exit();
    }
    $id = $segments[2] ?? null;
    $gateway = new StudentsGateway($database);
    $controller = new StudentsController($gateway);

    if ($method === 'GET' && count($segments) === 1) {
        $controller->index($page);
    } elseif ($method === 'POST' && count($segments) === 1) {
        $controller->store();
    } elseif ($method === 'PUT' && count($segments) === 2 && is_numeric($segments[1])) {
        $controller->update((int)$segments[1]);
    } elseif ($method === 'DELETE' && count($segments) === 2 && is_numeric($segments[1])) {
        $controller->destroy((int)$segments[1]);
    } else {
        http_response_code(404);
        echo json_encode(['success' => false, 'error' => 'Not Found']);
    }
} elseif ($segments[0] === 'auth') {
    $action = $segments[1] ?? null;

    $controller = new AuthController($AuthGateway, $jwtController);
    $controller->processRequest($_SERVER["REQUEST_METHOD"], $action);
} else {
    http_response_code(404);
    echo json_encode(['success' => false, 'error' => 'Not Found']);
}
