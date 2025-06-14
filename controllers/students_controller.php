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
