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