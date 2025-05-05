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
