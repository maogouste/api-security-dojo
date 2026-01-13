<?php
/**
 * API Security Dojo Auth Handlers
 */

namespace ApiSecurityDojo\Handlers;

use SQLite3;
use ApiSecurityDojo\Auth;

class AuthHandler
{
    public static function register(SQLite3 $db): void
    {
        $data = Auth::getJsonBody();
        $hash = password_hash($data['password'], PASSWORD_BCRYPT, ['cost' => 4]);

        $stmt = $db->prepare("INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'user')");
        $stmt->bindValue(1, $data['username']);
        $stmt->bindValue(2, $data['email']);
        $stmt->bindValue(3, $hash);

        if (!$stmt->execute()) {
            http_response_code(400);
            echo json_encode(['detail' => 'Username or email already exists']);
            return;
        }

        http_response_code(201);
        echo json_encode(['id' => $db->lastInsertRowID(), 'username' => $data['username'], 'email' => $data['email'], 'role' => 'user']);
    }

    public static function login(SQLite3 $db): void
    {
        $data = Auth::getJsonBody();

        $stmt = $db->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->bindValue(1, $data['username']);
        $result = $stmt->execute();
        $user = $result->fetchArray(SQLITE3_ASSOC);

        if (!$user) {
            http_response_code(401);
            echo json_encode(['detail' => 'User not found']); // VULNERABILITY: User enumeration
            return;
        }

        if (!password_verify($data['password'], $user['password_hash'])) {
            http_response_code(401);
            echo json_encode(['detail' => 'Incorrect password']); // VULNERABILITY: User enumeration
            return;
        }

        $token = Auth::createToken($user);
        echo json_encode(['access_token' => $token, 'token_type' => 'bearer', 'user_id' => $user['id'], 'role' => $user['role']]);
    }

    public static function me(SQLite3 $db): void
    {
        $user = Auth::requireAuth($db);
        echo json_encode($user);
    }
}
