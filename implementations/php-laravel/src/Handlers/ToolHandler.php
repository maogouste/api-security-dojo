<?php
/**
 * API Security Dojo Tool Handlers
 */

namespace ApiSecurityDojo\Handlers;

use ApiSecurityDojo\Auth;

class ToolHandler
{
    public static function ping(): void
    {
        $data = Auth::getJsonBody();
        $host = $data['host'] ?? '';

        // VULNERABILITY V07: Command injection
        $output = shell_exec("ping -c 1 $host 2>&1");

        echo json_encode([
            'success' => $output !== null,
            'command' => "ping -c 1 $host",
            'output' => $output,
        ]);
    }

    public static function dns(): void
    {
        $data = Auth::getJsonBody();
        $domain = $data['domain'] ?? '';

        // VULNERABILITY V07: Command injection
        $output = shell_exec("nslookup $domain 2>&1");

        echo json_encode(['domain' => $domain, 'output' => $output]);
    }

    public static function debug(): void
    {
        // VULNERABILITY V08: Exposes sensitive debug info
        echo json_encode([
            'php_version' => PHP_VERSION,
            'env_vars' => $_ENV,
            'server' => $_SERVER,
        ]);
    }
}
