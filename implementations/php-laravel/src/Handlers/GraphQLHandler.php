<?php
/**
 * API Security Dojo GraphQL Handler
 *
 * VULNERABILITIES:
 * - G01: Introspection enabled (schema accessible)
 * - G02: No query depth limits (nested queries possible)
 * - G03: Batching enabled without limits
 * - G04: Field suggestions in error messages
 * - G05: No authentication checks on sensitive queries
 */

namespace ApiSecurityDojo\Handlers;

use SQLite3;
use ApiSecurityDojo\Auth;

class GraphQLHandler
{
    public static function handle(SQLite3 $db): void
    {
        $body = json_decode(file_get_contents('php://input'), true);

        // VULNERABILITY G03: Process batched queries without any limits
        if (isset($body[0])) {
            // Batched query - process each one without limits
            $results = [];
            foreach ($body as $operation) {
                $results[] = self::executeQuery($db, $operation['query'] ?? '', $operation['variables'] ?? []);
            }
            echo json_encode($results);
            return;
        }

        // Single query
        $result = self::executeQuery($db, $body['query'] ?? '', $body['variables'] ?? []);
        echo json_encode($result);
    }

    private static function executeQuery(SQLite3 $db, string $query, array $variables): array
    {
        // VULNERABILITY G01: Introspection enabled
        if (strpos($query, '__schema') !== false) {
            return self::handleIntrospection();
        }

        // VULNERABILITY G05: No auth check - exposes all users with sensitive data
        if (strpos($query, 'users') !== false && strpos($query, 'orders') !== false) {
            return self::handleUsersWithOrders($db, $query);
        }

        // Simple users query (G05)
        if (strpos($query, 'users') !== false) {
            return self::handleUsers($db);
        }

        // Orders query (G05: no auth)
        if (strpos($query, 'orders') !== false) {
            return self::handleOrders($db, $query);
        }

        // Products query
        if (strpos($query, 'products') !== false) {
            return self::handleProducts($db);
        }

        // Login mutation
        if (preg_match('/login.*username.*["\']([^"\']+)["\'].*password.*["\']([^"\']+)["\']/', $query, $m) ||
            preg_match('/mutation.*login.*\(.*username.*["\']([^"\']+)["\'].*password.*["\']([^"\']+)["\']/', $query, $m)) {
            return self::handleLogin($db, $m[1], $m[2]);
        }

        // updateUser mutation (G05: no auth check)
        if (preg_match('/updateUser.*id.*(\d+)/', $query, $m)) {
            return self::handleUpdateUser($db, $query, (int)$m[1]);
        }

        // VULNERABILITY G04: Field suggestions in error messages
        return self::handleUnknownQuery($query);
    }

    private static function handleIntrospection(): array
    {
        return [
            'data' => [
                '__schema' => [
                    'queryType' => ['name' => 'Query'],
                    'mutationType' => ['name' => 'Mutation'],
                    'types' => [
                        [
                            'name' => 'User',
                            'kind' => 'OBJECT',
                            'fields' => [
                                ['name' => 'id', 'type' => ['name' => 'Int']],
                                ['name' => 'username', 'type' => ['name' => 'String']],
                                ['name' => 'email', 'type' => ['name' => 'String']],
                                ['name' => 'role', 'type' => ['name' => 'String']],
                                ['name' => 'ssn', 'type' => ['name' => 'String']],
                                ['name' => 'creditCard', 'type' => ['name' => 'String']],
                                ['name' => 'secretNote', 'type' => ['name' => 'String']],
                                ['name' => 'apiKey', 'type' => ['name' => 'String']],
                                ['name' => 'orders', 'type' => ['name' => '[Order]']],
                            ],
                        ],
                        [
                            'name' => 'Order',
                            'kind' => 'OBJECT',
                            'fields' => [
                                ['name' => 'id', 'type' => ['name' => 'Int']],
                                ['name' => 'userId', 'type' => ['name' => 'Int']],
                                ['name' => 'status', 'type' => ['name' => 'String']],
                                ['name' => 'totalAmount', 'type' => ['name' => 'Float']],
                                ['name' => 'shippingAddress', 'type' => ['name' => 'String']],
                                ['name' => 'notes', 'type' => ['name' => 'String']],
                                ['name' => 'user', 'type' => ['name' => 'User']],
                            ],
                        ],
                        [
                            'name' => 'Product',
                            'kind' => 'OBJECT',
                            'fields' => [
                                ['name' => 'id', 'type' => ['name' => 'Int']],
                                ['name' => 'name', 'type' => ['name' => 'String']],
                                ['name' => 'description', 'type' => ['name' => 'String']],
                                ['name' => 'price', 'type' => ['name' => 'Float']],
                                ['name' => 'internalNotes', 'type' => ['name' => 'String']],
                                ['name' => 'supplierCost', 'type' => ['name' => 'Float']],
                            ],
                        ],
                    ],
                ],
            ],
        ];
    }

    private static function handleUsersWithOrders(SQLite3 $db, string $query): array
    {
        // VULNERABILITY G02: Deep nesting - users with orders with user...
        $results = $db->query("SELECT id, username, email, role, ssn, credit_card, secret_note, api_key FROM users");
        $users = [];
        while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
            $user = [
                'id' => $row['id'],
                'username' => $row['username'],
                'email' => $row['email'],
                'role' => $row['role'],
                'ssn' => $row['ssn'],
                'creditCard' => $row['credit_card'],
                'secretNote' => $row['secret_note'],
                'apiKey' => $row['api_key'],
                'orders' => [],
            ];

            // Get orders for this user (G02: enables nesting)
            $orderResults = $db->query("SELECT * FROM orders WHERE user_id = {$row['id']}");
            while ($order = $orderResults->fetchArray(SQLITE3_ASSOC)) {
                $orderData = [
                    'id' => $order['id'],
                    'userId' => $order['user_id'],
                    'status' => $order['status'],
                    'totalAmount' => $order['total_amount'],
                    'shippingAddress' => $order['shipping_address'],
                    'notes' => $order['notes'],
                ];

                // G02: If query contains nested user in orders, include it (circular!)
                if (preg_match('/orders\s*\{[^}]*user/', $query)) {
                    $orderData['user'] = [
                        'id' => $row['id'],
                        'username' => $row['username'],
                        'email' => $row['email'],
                        'role' => $row['role'],
                        'ssn' => $row['ssn'],
                        'creditCard' => $row['credit_card'],
                    ];
                }

                $user['orders'][] = $orderData;
            }
            $users[] = $user;
        }
        return ['data' => ['users' => $users]];
    }

    private static function handleUsers(SQLite3 $db): array
    {
        $results = $db->query("SELECT id, username, email, role, ssn, credit_card, secret_note, api_key FROM users");
        $users = [];
        while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
            $users[] = [
                'id' => $row['id'],
                'username' => $row['username'],
                'email' => $row['email'],
                'role' => $row['role'],
                'ssn' => $row['ssn'],
                'creditCard' => $row['credit_card'],
                'secretNote' => $row['secret_note'],
                'apiKey' => $row['api_key'],
            ];
        }
        return ['data' => ['users' => $users]];
    }

    private static function handleOrders(SQLite3 $db, string $query): array
    {
        $results = $db->query("SELECT * FROM orders");
        $orders = [];
        while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
            $order = [
                'id' => $row['id'],
                'userId' => $row['user_id'],
                'status' => $row['status'],
                'totalAmount' => $row['total_amount'],
                'shippingAddress' => $row['shipping_address'],
                'notes' => $row['notes'],
            ];

            // G02: If query requests user, include it
            if (strpos($query, 'user') !== false) {
                $userResult = $db->query("SELECT * FROM users WHERE id = {$row['user_id']}");
                $u = $userResult->fetchArray(SQLITE3_ASSOC);
                if ($u) {
                    $order['user'] = [
                        'id' => $u['id'],
                        'username' => $u['username'],
                        'email' => $u['email'],
                        'ssn' => $u['ssn'],
                        'creditCard' => $u['credit_card'],
                    ];
                }
            }
            $orders[] = $order;
        }
        return ['data' => ['orders' => $orders]];
    }

    private static function handleProducts(SQLite3 $db): array
    {
        $results = $db->query("SELECT * FROM products");
        $products = [];
        while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
            $products[] = [
                'id' => $row['id'],
                'name' => $row['name'],
                'description' => $row['description'],
                'price' => $row['price'],
                'internalNotes' => $row['internal_notes'],
                'supplierCost' => $row['supplier_cost'],
            ];
        }
        return ['data' => ['products' => $products]];
    }

    private static function handleLogin(SQLite3 $db, string $username, string $password): array
    {
        $stmt = $db->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->bindValue(1, $username);
        $result = $stmt->execute();
        $user = $result->fetchArray(SQLITE3_ASSOC);

        if ($user && password_verify($password, $user['password_hash'])) {
            $token = Auth::createToken($user);
            return [
                'data' => [
                    'login' => [
                        'accessToken' => $token,
                        'tokenType' => 'bearer',
                        'userId' => $user['id'],
                        'role' => $user['role'],
                    ],
                ],
            ];
        }
        return ['errors' => [['message' => 'Invalid credentials']]];
    }

    private static function handleUpdateUser(SQLite3 $db, string $query, int $id): array
    {
        if (preg_match('/role.*["\']([^"\']+)["\']/', $query, $roleMatch)) {
            $db->exec("UPDATE users SET role = '{$roleMatch[1]}' WHERE id = $id");
        }
        $stmt = $db->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->bindValue(1, $id);
        $result = $stmt->execute();
        $user = $result->fetchArray(SQLITE3_ASSOC);
        return [
            'data' => [
                'updateUser' => [
                    'id' => $user['id'],
                    'username' => $user['username'],
                    'email' => $user['email'],
                    'role' => $user['role'],
                ],
            ],
        ];
    }

    private static function handleUnknownQuery(string $query): array
    {
        $validFields = ['users', 'user', 'products', 'product', 'orders', 'order', 'login', 'updateUser'];
        preg_match('/\{\s*(\w+)/', $query, $fieldMatch);
        $requestedField = $fieldMatch[1] ?? '';

        if ($requestedField && !in_array($requestedField, $validFields)) {
            // G04: Suggest similar fields
            $suggestions = array_filter($validFields, function($f) use ($requestedField) {
                return levenshtein($requestedField, $f) <= 3;
            });

            $errorMsg = "Cannot query field \"$requestedField\" on type \"Query\".";
            if (!empty($suggestions)) {
                $errorMsg .= " Did you mean " . implode(' or ', array_map(function($s) {
                    return "\"$s\"";
                }, $suggestions)) . "?";
            }

            return ['errors' => [['message' => $errorMsg]]];
        }

        return ['data' => null, 'errors' => [['message' => 'Query not supported']]];
    }
}
