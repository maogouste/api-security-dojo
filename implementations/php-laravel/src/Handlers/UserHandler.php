<?php
/**
 * API Security Dojo User Handlers
 */

namespace ApiSecurityDojo\Handlers;

use SQLite3;
use ApiSecurityDojo\Auth;

class UserHandler
{
    public static function listUsers(SQLite3 $db): void
    {
        $results = $db->query("SELECT id, username, email, role, is_active, ssn, credit_card, secret_note, api_key, created_at FROM users");
        $users = [];
        while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
            $users[] = $row;
        }
        echo json_encode($users);
    }

    public static function getUser(SQLite3 $db, int $id): void
    {
        // VULNERABILITY V01: No authorization check
        $stmt = $db->prepare("SELECT id, username, email, role, is_active, ssn, credit_card, secret_note, api_key, created_at FROM users WHERE id = ?");
        $stmt->bindValue(1, $id);
        $result = $stmt->execute();
        $user = $result->fetchArray(SQLITE3_ASSOC);

        if (!$user) {
            http_response_code(404);
            echo json_encode(['detail' => 'User not found']);
            return;
        }

        echo json_encode($user);
    }

    public static function updateUser(SQLite3 $db, int $id): void
    {
        $data = Auth::getJsonBody();

        // VULNERABILITY V05: Mass assignment
        foreach ($data as $field => $value) {
            if ($field === 'password') {
                $hash = password_hash($value, PASSWORD_BCRYPT, ['cost' => 4]);
                $db->exec("UPDATE users SET password_hash = '$hash' WHERE id = $id");
            } else {
                $db->exec("UPDATE users SET $field = '$value' WHERE id = $id");
            }
        }

        $stmt = $db->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->bindValue(1, $id);
        $result = $stmt->execute();
        echo json_encode($result->fetchArray(SQLITE3_ASSOC));
    }

    public static function deleteUser(SQLite3 $db, int $id): void
    {
        $db->exec("DELETE FROM users WHERE id = $id");
        echo json_encode(['message' => 'User deleted']);
    }

    // Legacy API - VULNERABILITY V09
    public static function listUsersV1(SQLite3 $db): void
    {
        $results = $db->query("SELECT * FROM users");
        $users = [];
        while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
            $users[] = $row;
        }
        echo json_encode($users);
    }

    public static function getUserV1(SQLite3 $db, int $id): void
    {
        $stmt = $db->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->bindValue(1, $id);
        $result = $stmt->execute();
        echo json_encode($result->fetchArray(SQLITE3_ASSOC));
    }
}
