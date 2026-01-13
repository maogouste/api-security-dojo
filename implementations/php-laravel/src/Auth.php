<?php
/**
 * API Security Dojo Authentication
 */

namespace ApiSecurityDojo;

use SQLite3;

class Auth
{
    public static function createToken(array $user): string
    {
        $header = base64_encode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
        $payload = base64_encode(json_encode([
            'sub' => $user['username'],
            'user_id' => $user['id'],
            'role' => $user['role'],
            'exp' => time() + 86400,
        ]));
        $signature = base64_encode(hash_hmac('sha256', "$header.$payload", Config::JWT_SECRET, true));
        return "$header.$payload.$signature";
    }

    public static function parseToken(string $token): ?array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) return null;

        [$header, $payload, $signature] = $parts;
        $expectedSig = base64_encode(hash_hmac('sha256', "$header.$payload", Config::JWT_SECRET, true));

        if ($signature !== $expectedSig) return null;

        $data = json_decode(base64_decode($payload), true);
        if ($data['exp'] < time()) return null;

        return $data;
    }

    public static function getAuthUser(SQLite3 $db): ?array
    {
        $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if (!preg_match('/^Bearer\s+(.+)$/', $auth, $m)) return null;

        $payload = self::parseToken($m[1]);
        if (!$payload) return null;

        $stmt = $db->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->bindValue(1, $payload['user_id']);
        $result = $stmt->execute();
        return $result->fetchArray(SQLITE3_ASSOC) ?: null;
    }

    public static function requireAuth(SQLite3 $db): array
    {
        $user = self::getAuthUser($db);
        if (!$user) {
            http_response_code(401);
            echo json_encode(['detail' => 'Not authenticated']);
            exit;
        }
        return $user;
    }

    public static function getJsonBody(): array
    {
        return json_decode(file_get_contents('php://input'), true) ?? [];
    }
}
