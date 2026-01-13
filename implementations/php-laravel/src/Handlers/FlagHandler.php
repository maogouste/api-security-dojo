<?php
/**
 * API Security Dojo Flag Handlers
 */

namespace ApiSecurityDojo\Handlers;

use SQLite3;
use ApiSecurityDojo\Auth;

class FlagHandler
{
    public static function listChallenges(SQLite3 $db): void
    {
        $results = $db->query("SELECT challenge_id, description FROM flags");
        $challenges = [];
        while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
            $challenges[] = [
                'id' => $row['challenge_id'],
                'description' => $row['description'],
                'category' => strpos($row['challenge_id'], 'G') === 0 ? 'graphql' : 'rest',
            ];
        }
        echo json_encode($challenges);
    }

    public static function submitFlag(SQLite3 $db): void
    {
        $data = Auth::getJsonBody();
        $flag = $data['flag'] ?? '';

        $stmt = $db->prepare("SELECT challenge_id, description FROM flags WHERE flag_value = ?");
        $stmt->bindValue(1, $flag);
        $result = $stmt->execute();
        $row = $result->fetchArray(SQLITE3_ASSOC);

        if (!$row) {
            echo json_encode(['success' => false, 'message' => 'Invalid flag']);
            return;
        }

        echo json_encode([
            'success' => true,
            'message' => "Congratulations! You solved challenge {$row['challenge_id']}!",
            'challenge_id' => $row['challenge_id'],
        ]);
    }
}
