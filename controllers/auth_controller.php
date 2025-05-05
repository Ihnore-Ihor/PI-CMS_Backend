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