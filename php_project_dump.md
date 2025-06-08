# Зведення PHP файлів та їхнього вмісту

<!--
  Цей файл містить список PHP файлів та їхній повний вміст.
  Кожен файл представлений у наступному форматі:

  ## File: [відносний/шлях/до/файлу.php]

  ```php
  <?php
  // Вміст файлу тут...
  ?>
  ```
-->

## File: database/database.php

```php
<?php
class Database {
    private $host = 'localhost';
    private $db_name = 'CMS';
    private $username = 'root';
    private $password = 'root';
    private $conn;

    public function connect() {
        $this->conn = null;
        try {
            $this->conn = new PDO(
                "mysql:host={$this->host};dbname={$this->db_name};charset=utf8",
                $this->username,
                $this->password
            );
            $this->conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->conn->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            throw new Exception("Database connection failed: " . $e->getMessage());
        }
        return $this->conn;
    }
}

```

## File: index.php

```php
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

```

## File: error_handler.php

```php
<?php
class ErrorHandler
{
    public static function handleException(Throwable $exception): void
    {
        http_response_code(500);

        echo json_encode([
            "code" => $exception->getCode(),
            "message" => $exception->getMessage(),
            "file" => $exception->getFile(),
            "line" => $exception->getLine()
        ]);
    }

    /**
     * @throws ErrorException
     */
    public static function handleError(
        int $errno,
        string $errstr,
        string $errfile,
        int $errline
    ): bool {
        throw new ErrorException($errstr, 0, $errno, $errfile, $errline);
    }
}
```

## File: gateways/students_gateway.php

```php
<?php
class StudentsGateway {
    private $db;
    private $perPage = 5;

    public function __construct(Database $database) {
        $this->db = $database->connect();
    }

    public function getAll($page) {
        $offset = ($page - 1) * $this->perPage;
        $sql = "SELECT * FROM students LIMIT :limit OFFSET :offset";
        $stmt = $this->db->prepare($sql);
        $stmt->bindValue(':limit', $this->perPage, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();
        $students = $stmt->fetchAll();

        $sql = "SELECT COUNT(*) as total FROM students";
        $stmt = $this->db->query($sql);
        $total = $stmt->fetch()['total'];

        return ['students' => $students, 'total' => $total, 'perPage' => $this->perPage];
    }

    public function create($data) {
        $sql = "INSERT INTO students (username, password, group_name, first_name, last_name, gender, date_of_birth, status) 
                VALUES (:username, :password, :group_name, :first_name, :last_name, :gender, :date_of_birth, :status)";
        $stmt = $this->db->prepare($sql);
        $username = "{$data['first_name']}{$data['last_name']}{$data['date_of_birth']}";

        $stmt->bindValue(':username', $username );
        $stmt->bindValue(':password', $data['date_of_birth']);
        $stmt->bindValue(':group_name', $data['group_name']);
        $stmt->bindValue(':first_name', $data['first_name']);
        $stmt->bindValue(':last_name', $data['last_name']);
        $stmt->bindValue(':gender', $data['gender']);
        $stmt->bindValue(':date_of_birth', $data['date_of_birth']);
        $stmt->bindValue(':status', false, PDO::PARAM_BOOL);
        $stmt->execute();
        return $this->db->lastInsertId();
    }

    public function update($id, $data) {
        $sql = "UPDATE students SET 
                username = :username,
                password = :password,
                group_name = :group_name, 
                first_name = :first_name, 
                last_name = :last_name, 
                gender = :gender, 
                date_of_birth = :date_of_birth
                WHERE id = :id";

        $stmt = $this->db->prepare($sql);
        $username = "{$data['first_name']}{$data['last_name']}{$data['date_of_birth']}";

        $stmt->bindValue(':username', $username );
        $stmt->bindValue(':password', $data['date_of_birth']);
        $stmt->bindValue(':group_name', $data['group_name']);
        $stmt->bindValue(':first_name', $data['first_name']);
        $stmt->bindValue(':last_name', $data['last_name']);
        $stmt->bindValue(':gender', $data['gender']);
        $stmt->bindValue(':date_of_birth', $data['date_of_birth']);
        $stmt->bindValue(':id', $id, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->rowCount();
    }

    public function delete($id) {
        $sql = "DELETE FROM students WHERE id = :id";
        $stmt = $this->db->prepare($sql);
        $stmt->bindValue(':id', $id, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->rowCount();
    }

    public function getById($id) {
        $sql = "SELECT * FROM students WHERE id = :id";
        $stmt = $this->db->prepare($sql);
        $stmt->bindValue(':id', $id, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetch();
    }

    public function findByDetails($first_name, $last_name, $date_of_birth, $group_name, $excludeId = null) {
        $sql = "SELECT * FROM students 
                WHERE first_name = :first_name 
                AND last_name = :last_name 
                AND date_of_birth = :date_of_birth
                AND group_name = :group_name";
        if ($excludeId !== null) {
            $sql .= " AND id != :exclude_id";
        }
        $stmt = $this->db->prepare($sql);
        $params = [
            ':first_name' => $first_name,
            ':last_name' => $last_name,
            ':date_of_birth' => $date_of_birth,
            ':group_name' => $group_name
        ];
        if ($excludeId !== null) {
            $params[':exclude_id'] = $excludeId;
        }
        $stmt->execute($params);
        return $stmt->fetch();
    }

    public function fetchAllStudents() {
        $sql = "SELECT * FROM students";
        $stmt = $this->db->query($sql);
        $students = $stmt->fetchAll();

        return ['students' => $students, 'total' => count($students)];
    }
}

```

## File: gateways/auth_gateway.php

```php
<?php
class AuthGateway
{
    private PDO $conn;

    public function __construct(Database $database)
    {
        $this->conn = $database->connect();
    }

    public function authenticate(string $username, string $password): array | false
    {
        $sql = "SELECT id, username, first_name, last_name, password 
                FROM students 
                WHERE username = :username";

        $stmt = $this->conn->prepare($sql);
        $stmt->bindValue(":username", $username, PDO::PARAM_STR);
        $stmt->execute();

        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && $password === $user["password"]) {
            unset($user["password"]);
            return $user;
        }

        return false;
    }

    public function changeStatus(string $id, bool $status): bool
    {
        $sql = "UPDATE students
                SET status = :status
                WHERE id = :id";

        $stmt = $this->conn->prepare($sql);
        $stmt->bindValue(":id", $id, PDO::PARAM_STR);
        $stmt->bindValue(":status", $status, PDO::PARAM_BOOL);
        $stmt->execute();

        return $stmt->rowCount() > 0;
    }
}
```

## File: controllers/auth_controller.php

```php
<?php
class AuthController
{
    public function __construct(private AuthGateway $gateway, private JwtController $jwtController) {}

    public function processRequest(string $method, string $action): void
    {
        switch ($action) {
            case 'login':
                $this->processLoginRequest($method);
                break;
            case 'logout':
                $this->processLogoutRequest($method);
                break;
            default:
                http_response_code(404);
                echo json_encode(["message" => "Action not found"]);
                break;
        }
    }

    private function processLoginRequest(string $method): void
    {
        if ($method !== "POST") {
            http_response_code(405);
            header("Allow: POST");
            return;
        }

        $data = (array) json_decode(file_get_contents("php://input"), true);

        $errors = $this->validateLoginData($data);

        if (!empty($errors)) {
            http_response_code(422);
            echo json_encode(["errors" => $errors]);
            return;
        }

        $user = $this->gateway->authenticate($data["username"], $data["password"]);

        if (!$user) {
            http_response_code(401);
            echo json_encode(["message" => "Invalid credentials"]);
            return;
        }

        $token = $this->jwtController->jwt_encode(["sub" => $user["id"],
            "exp" => time() + 60 * 60]);

        $this->gateway->changeStatus($user["id"], true);

        http_response_code(200);
        echo json_encode([
            "message" => "Login successful",
            "token" => $token,
            "user" => [
                "first_name" => $user['first_name'],
                "last_name" => $user['last_name']
            ]
        ]);
    }

    private function processLogoutRequest(string $method): void
    {
        if ($method !== "POST") {
            http_response_code(405);
            header("Allow: POST");
            return;
        }

        $headers = apache_request_headers();
        $token = isset($headers["Authorization"]) ? str_replace("Bearer ", "", $headers["Authorization"]) : null;

        if (!$token) {
            http_response_code(401);
            echo json_encode(["message" => "No token provided"]);
            return;
        }

        $token = $this->jwtController->jwt_decode($token);
        $this->gateway->changeStatus($token["sub"], false);

        http_response_code(200);
        echo json_encode(["message" => "Logout successful"]);
    }

    private function validateLoginData(array $data): array
    {
        $errors = [];

        if (empty($data["username"])) {
            $errors[] = "username is required";
        } elseif (!preg_match("/^[A-Za-zА-Яа-я'\-\d]{2,50}$/", $data["username"])) {
            $errors[] = "Invalid username format";
        }

        if (empty($data["password"])) {
            $errors[] = "Password is required";
        }

        return $errors;
    }
}
```

## File: controllers/auth.php

```php
<?php
class Auth {
    public function __construct(private JwtController $jwtController, private AuthGateway $gateway){}

    public function authenticate() {
        $headers = apache_request_headers();
        $token = isset($headers["Authorization"]) ? str_replace("Bearer ", "", $headers["Authorization"]) : null;
        if(!isset($token)) {
            http_response_code(401);
            echo json_encode(["message" => "Not authorized. No token provided", "ghj"=> $headers]);
            return false;
        }

        try{
            $payload = $this->jwtController->jwt_decode($token);
        } catch (InvalidArgumentException $e) {
            http_response_code(401);
            header('WWW-Authenticate: Bearer');
            echo json_encode(["message" => "Not authorized. Invalid token format"]);
            return false;
        } catch (Exception $e) {
            if ($e->getMessage() === "Access token expired.") {
                if (isset($payload["sub"])) {
                    $this->gateway->changeStatus($payload["sub"], false);
                }
                http_response_code(401);
                header('WWW-Authenticate: Bearer');
                echo json_encode(["message" => "Not authorized. Token expired"]);
                return false;
            }
            http_response_code(401);
            header('WWW-Authenticate: Bearer');
            echo json_encode(["message" => "Not authorized. Invalid token"]);
            return false;
        }

        return $payload["sub"];
    }
}

```

## File: controllers/students_controller.php

```php
<?php
class StudentsController {
    private $gateway;

    public function __construct($gateway) {
        $this->gateway = $gateway;
    }

    public function index($page) {
        $result = $this->gateway->getAll($page);
        echo json_encode([
            'success' => true,
            'students' => $result['students'],
            'total' => $result['total'],
            'perPage' => $result['perPage']
        ]);
    }

    public function store() {
        $data = json_decode(file_get_contents('php://input'), true);
        $errors = $this->validate($data);

        if (!empty($errors)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'errors' => $errors]);
            return;
        }

        $id = $this->gateway->create($data);
        http_response_code(201);
        echo json_encode(['success' => true, 'id' => $id]);
    }

    public function update($id) {
        $data = json_decode(file_get_contents('php://input'), true);
        $errors = $this->validate($data, true);

        if (!empty($errors)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'errors' => $errors]);
            return;
        }

        if (!$this->gateway->getById($id)) {
            http_response_code(404);
            echo json_encode(['success' => false, 'error' => 'Student not found']);
            return;
        }

        $this->gateway->update($id, $data);
        echo json_encode(['success' => true]);
    }

    public function destroy($id) {
        if (!$this->gateway->getById($id)) {
            http_response_code(404);
            echo json_encode(['success' => false, 'error' => 'Student not found']);
            return;
        }

        $this->gateway->delete($id);
        echo json_encode(['success' => true]);
    }

    public function getAllStudents() {
        $result = $this->gateway->fetchAllStudents();
        echo json_encode([
            'success' => true,
            'students' => $result['students'],
            'total' => $result['total']
        ]);
    }

    private function validate($data, $isUpdate = false) {
        $errors = [];

        if (empty($data['group_name']) || !in_array($data['group_name'], ['PZ-22', 'PZ-21', 'PZ-23', 'PZ-24', 'PZ-25',
                'PZ-26', 'PZ-11', 'PZ-12', 'PZ-13', 'PZ-14', 'PZ-15', 'PZ-16', 'PZ-17'])) {
            $errors['group_name'] = 'Group is required';
        }

        if (empty($data['first_name']) || !preg_match('/^[A-Za-zА-Яа-я\'\-]{2,50}$/', $data['first_name'])) {
            $errors['first_name'] = 'First name must be 2-50 letters';
        }

        if (empty($data['last_name']) || !preg_match('/^[A-Za-zА-Яа-я\'\-]{2,50}$/', $data['last_name'])) {
            $errors['last_name'] = 'Last name must be 2-50 letters';
        }

        if (empty($data['gender']) || !in_array($data['gender'], ['Male', 'Female', 'Other'])) {
            $errors['gender'] = 'Gender must be Male, Female, or Other';
        }

        if (empty($data['date_of_birth']) || !preg_match('/^\d{4}-\d{2}-\d{2}$/', $data['date_of_birth'])) {
            $errors['date_of_birth'] = 'Valid date of birth is required';
        } else {
            $birthDate = new DateTime($data['date_of_birth']);
            $today = new DateTime();
            if ($birthDate >= $today) {
                $errors['date_of_birth'] = 'Date of birth cannot be in the future';
            }
        }

        if (!$isUpdate) {
            $existingStudent = $this->gateway->findByDetails(
                $data['first_name'] ?? '',
                $data['last_name'] ?? '',
                $data['date_of_birth'] ?? '',
                $data['group_name'] ?? ''
            );
            if ($existingStudent) {
                $errors['duplicate'] = 'A student with this first name, last name, date of birth, group name already exists';
            }
        } else {
            if (empty($data['id']) || !is_numeric($data['id'])) {
                $errors['id'] = 'Student ID is required for updates';
            } else {
                $existingStudent = $this->gateway->findByDetails(
                    $data['first_name'] ?? '',
                    $data['last_name'] ?? '',
                    $data['date_of_birth'] ?? '',
                    $data['id']
                );
                if ($existingStudent) {
                    $errors['duplicate'] = 'Another student with this first name, last name, date of birth, group name already exists';
                }
            }
        }

        return $errors;
    }
}

```

## File: controllers/jwt_controller.php

```php
<?php
class JwtController {
    private $key = "supersecret";

    public function jwt_encode(array $payload): string
    {
        $header = json_encode([
            "alg" => "HS256",
            "typ" => "JWT"
        ]);

        $header = $this->base64url_encode($header);
        $payload = json_encode($payload);
        $payload = $this->base64url_encode($payload);

        $signature = hash_hmac("sha256", $header . "." . $payload, $this->key, true);
        $signature = $this->base64url_encode($signature);
        return $header . "." . $payload . "." . $signature;
    }

    public function jwt_decode(string $token): array
    {
        if (preg_match(
                "/^(?<header>.+)\.(?<payload>.+)\.(?<signature>.+)$/",
                $token,
                $matches
            ) !== 1) {
            throw new InvalidArgumentException("JWT is incorrect.");
        }

        $signature = hash_hmac(
            "sha256",
            $matches["header"] . "." . $matches["payload"],
            $this->key,
            true
        );

        $signature_from_token = $this->base64url_decode($matches["signature"]);

        if (! hash_equals($signature, $signature_from_token)) {
            throw new Exception("Hash is incorrect. JWT is refused.");
        }

        $payload = json_decode($this->base64url_decode($matches["payload"]), true);

        if ($payload["exp"] < time()) {
            throw new Exception("Access token expired.");
        }

        return $payload;
    }

    /**
     * Encode data to Base64URL
     * @param string $data
     * @return boolean|string
     */
    public function base64url_encode($data)
    {
        $b64 = base64_encode($data);

        if ($b64 === false) {
            return false;
        }
        $url = strtr($b64, '+/', '-_');

        return rtrim($url, '=');
    }

    /**
     * Decode data from Base64URL
     * @param string $data
     * @param boolean $strict
     * @return boolean|string
     */
    public function base64url_decode($data, $strict = false)
    {
        $b64 = strtr($data, '-_', '+/');

        return base64_decode($b64, $strict);
    }
}

```

PHP файли не знайдено у директорії пошуку.
