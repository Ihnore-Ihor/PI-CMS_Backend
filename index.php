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

$allowed_origins = [
    "http://127.0.0.1:5500",
    "http://localhost:63342",
    "http://localhost:5500",
    "http://localhost:8888",
    "http://localhost:3000"
];

// Get the Origin header from the request
$origin = isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : '';

// Check if the origin is in our allowed list
if (in_array($origin, $allowed_origins)) {
    header("Access-Control-Allow-Origin: " . $origin);
    header("Access-Control-Allow-Credentials: true");
    header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
    header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With");
    header("Access-Control-Max-Age: 3600"); // Cache preflight for 1 hour
}

header("Content-Type: application/json; charset=UTF-8");

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204); // No content needed for preflight
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
    } elseif ($method === 'GET' && count($segments) === 2 && $segments[1] === 'all') {
        $controller->getAllStudents();
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
