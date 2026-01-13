<?php
/**
 * API Security Dojo Product Handlers
 */

namespace ApiSecurityDojo\Handlers;

use SQLite3;

class ProductHandler
{
    public static function listProducts(SQLite3 $db): void
    {
        $search = $_GET['search'] ?? '';

        if ($search) {
            // VULNERABILITY V06: SQL Injection
            $query = "SELECT * FROM products WHERE name LIKE '%$search%' OR description LIKE '%$search%'";
            $results = $db->query($query);
        } else {
            $results = $db->query("SELECT * FROM products WHERE is_active = 1");
        }

        $products = [];
        while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
            $products[] = $row;
        }
        echo json_encode($products);
    }

    public static function getProduct(SQLite3 $db, int $id): void
    {
        $stmt = $db->prepare("SELECT * FROM products WHERE id = ?");
        $stmt->bindValue(1, $id);
        $result = $stmt->execute();
        echo json_encode($result->fetchArray(SQLITE3_ASSOC));
    }
}
