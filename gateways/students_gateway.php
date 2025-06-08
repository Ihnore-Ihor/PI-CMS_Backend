<?php
class StudentsGateway {
    private $db;
    private $perPage = 5;

    public function __construct(Database $database) {
        $this->db = $database->connect();
        $this->db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
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
        $sql = "SELECT id, username, group_name, first_name, last_name, gender, date_of_birth, status FROM students";
        $stmt = $this->db->query($sql);
        $students = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return [
            'success' => true,
            'students' => $students,
            'total' => count($students)
        ];
    }
}
