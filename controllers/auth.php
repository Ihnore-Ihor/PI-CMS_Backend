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
