<?php
/**
 * API Security Dojo - PHP Implementation
 *
 * Deliberately vulnerable API for security learning.
 * WARNING: This API contains intentional security vulnerabilities.
 * Do NOT deploy in production.
 */

// Autoloader
spl_autoload_register(function ($class) {
    $prefix = 'ApiSecurityDojo\\';
    $baseDir = __DIR__ . '/src/';

    if (strncmp($prefix, $class, strlen($prefix)) !== 0) {
        return;
    }

    $relativeClass = substr($class, strlen($prefix));
    $file = $baseDir . str_replace('\\', '/', $relativeClass) . '.php';

    if (file_exists($file)) {
        require $file;
    }
});

/**
 * Check if running in a production-like environment and block startup.
 * This application is INTENTIONALLY VULNERABLE and should NEVER
 * be deployed in production environments.
 */
function checkProductionEnvironment(): void {
    $indicators = [];

    $envVars = [
        'PRODUCTION', 'PROD', 'AWS_EXECUTION_ENV', 'AWS_LAMBDA_FUNCTION_NAME',
        'KUBERNETES_SERVICE_HOST', 'ECS_CONTAINER_METADATA_URI',
        'GOOGLE_CLOUD_PROJECT', 'HEROKU_APP_NAME', 'VERCEL', 'RENDER'
    ];

    foreach ($envVars as $var) {
        $value = getenv($var);
        if ($value !== false && $value !== '') {
            $indicators[$var] = $value;
        }
    }

    if (getenv('NODE_ENV') === 'production') {
        $indicators['NODE_ENV=production'] = 'true';
    }
    if (getenv('ENVIRONMENT') === 'production') {
        $indicators['ENVIRONMENT=production'] = 'true';
    }

    if (!empty($indicators)) {
        $message = <<<EOT

================================================================================
                    CRITICAL SECURITY WARNING
================================================================================

  API Security Dojo has detected a PRODUCTION-LIKE environment!

  Detected indicators:

EOT;
        foreach ($indicators as $k => $v) {
            $message .= "    - $k: $v\n";
        }
        $message .= <<<EOT

  THIS APPLICATION IS INTENTIONALLY VULNERABLE!
  It contains security vulnerabilities by design for educational purposes.

  DO NOT DEPLOY IN PRODUCTION - You WILL be compromised!

================================================================================

EOT;
        fwrite(STDERR, $message);

        if (getenv('DOJO_FORCE_START') !== 'true') {
            fwrite(STDERR, "  To override this safety check (NOT RECOMMENDED), set:\n");
            fwrite(STDERR, "    DOJO_FORCE_START=true\n\n");
            exit(1);
        } else {
            fwrite(STDERR, "  WARNING: DOJO_FORCE_START=true detected.\n");
            fwrite(STDERR, "  Proceeding despite production environment detection.\n");
            fwrite(STDERR, "  YOU HAVE BEEN WARNED!\n\n");
        }
    }
}

// Check production environment before proceeding
checkProductionEnvironment();

use ApiSecurityDojo\Config;
use ApiSecurityDojo\Database;
use ApiSecurityDojo\Auth;
use ApiSecurityDojo\Handlers\AuthHandler;
use ApiSecurityDojo\Handlers\UserHandler;
use ApiSecurityDojo\Handlers\ProductHandler;
use ApiSecurityDojo\Handlers\ToolHandler;
use ApiSecurityDojo\Handlers\FlagHandler;
use ApiSecurityDojo\Handlers\DocsHandler;
use ApiSecurityDojo\Handlers\GraphQLHandler;

// VULNERABILITY V08: CORS misconfiguration
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: *');
header('Access-Control-Allow-Headers: *');
header('Access-Control-Allow-Credentials: true');
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// Initialize database
$db = Database::getInstance();

// Router
$method = $_SERVER['REQUEST_METHOD'];
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$uri = rtrim($uri, '/');

// Route handling
try {
    switch (true) {
        case $uri === '' || $uri === '/':
            echo json_encode([
                'name' => 'API Security Dojo',
                'version' => '0.2.0',
                'mode' => Config::getMode(),
                'implementation' => 'PHP',
                'message' => 'Welcome to API Security Dojo - A deliberately vulnerable API',
            ]);
            break;

        case $uri === '/health':
            echo json_encode(['status' => 'healthy', 'implementation' => 'php']);
            break;

        // Auth routes
        case $uri === '/api/register' && $method === 'POST':
            AuthHandler::register($db);
            break;

        case $uri === '/api/login' && $method === 'POST':
            AuthHandler::login($db);
            break;

        case $uri === '/api/me' && $method === 'GET':
            AuthHandler::me($db);
            break;

        // Users routes
        case $uri === '/api/users' && $method === 'GET':
            UserHandler::listUsers($db);
            break;

        case preg_match('#^/api/users/(\d+)$#', $uri, $m) && $method === 'GET':
            UserHandler::getUser($db, (int)$m[1]);
            break;

        case preg_match('#^/api/users/(\d+)$#', $uri, $m) && $method === 'PUT':
            Auth::requireAuth($db);
            UserHandler::updateUser($db, (int)$m[1]);
            break;

        case preg_match('#^/api/users/(\d+)$#', $uri, $m) && $method === 'DELETE':
            Auth::requireAuth($db);
            UserHandler::deleteUser($db, (int)$m[1]);
            break;

        // Legacy API V1 - VULNERABILITY V09
        case $uri === '/api/v1/users' && $method === 'GET':
            UserHandler::listUsersV1($db);
            break;

        case preg_match('#^/api/v1/users/(\d+)$#', $uri, $m) && $method === 'GET':
            UserHandler::getUserV1($db, (int)$m[1]);
            break;

        // Products routes
        case $uri === '/api/products' && $method === 'GET':
            ProductHandler::listProducts($db);
            break;

        case preg_match('#^/api/products/(\d+)$#', $uri, $m) && $method === 'GET':
            ProductHandler::getProduct($db, (int)$m[1]);
            break;

        // Tools routes
        case $uri === '/api/tools/ping' && $method === 'POST':
            Auth::requireAuth($db);
            ToolHandler::ping();
            break;

        case $uri === '/api/tools/dns' && $method === 'POST':
            Auth::requireAuth($db);
            ToolHandler::dns();
            break;

        case $uri === '/api/tools/debug' && $method === 'GET':
            ToolHandler::debug();
            break;

        // Flags routes
        case $uri === '/api/challenges' && $method === 'GET':
            FlagHandler::listChallenges($db);
            break;

        case $uri === '/api/flags/submit' && $method === 'POST':
            Auth::requireAuth($db);
            FlagHandler::submitFlag($db);
            break;

        // Docs routes
        case $uri === '/api/docs/mode':
            DocsHandler::mode();
            break;

        case $uri === '/api/docs/stats':
            DocsHandler::stats();
            break;

        case $uri === '/api/docs/categories':
            DocsHandler::categories();
            break;

        case $uri === '/api/docs/vulnerabilities' && $method === 'GET':
            DocsHandler::vulnerabilities();
            break;

        case preg_match('#^/api/docs/vulnerabilities/([A-Z]\d+)$#', $uri, $m):
            DocsHandler::vulnerability($m[1]);
            break;

        // GraphQL
        case $uri === '/graphql' || $uri === '/graphql/':
            GraphQLHandler::handle($db);
            break;

        default:
            http_response_code(404);
            echo json_encode(['detail' => 'Not found']);
    }
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => $e->getMessage()]);
}
