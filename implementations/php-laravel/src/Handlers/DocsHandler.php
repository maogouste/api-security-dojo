<?php
/**
 * API Security Dojo Documentation Handlers
 */

namespace ApiSecurityDojo\Handlers;

use ApiSecurityDojo\Config;

class DocsHandler
{
    public static function mode(): void
    {
        $mode = Config::getMode();
        echo json_encode([
            'mode' => $mode,
            'documentation_enabled' => $mode === 'documentation',
            'description' => $mode === 'documentation'
                ? 'Documentation mode: Full exploitation details and remediation'
                : 'Challenge mode: Limited information, find vulnerabilities yourself',
        ]);
    }

    public static function stats(): void
    {
        $vulns = self::loadVulnerabilities();
        $stats = [
            'total' => count($vulns),
            'by_severity' => [],
            'by_category' => [],
            'rest_api' => 0,
            'graphql' => 0,
        ];

        foreach ($vulns as $v) {
            $stats['by_severity'][$v['severity']] = ($stats['by_severity'][$v['severity']] ?? 0) + 1;
            $stats['by_category'][$v['category']] = ($stats['by_category'][$v['category']] ?? 0) + 1;
            if (strpos($v['id'], 'V') === 0) $stats['rest_api']++;
            else $stats['graphql']++;
        }

        echo json_encode($stats);
    }

    public static function categories(): void
    {
        $vulns = self::loadVulnerabilities();
        $categories = [];

        foreach ($vulns as $v) {
            $cat = $v['category'];
            if (!isset($categories[$cat])) {
                $categories[$cat] = ['name' => $cat, 'count' => 0, 'vulnerabilities' => []];
            }
            $categories[$cat]['count']++;
            $categories[$cat]['vulnerabilities'][] = $v['id'];
        }

        echo json_encode(array_values($categories));
    }

    public static function vulnerabilities(): void
    {
        $vulns = self::loadVulnerabilities();
        $category = $_GET['category'] ?? '';
        $severity = $_GET['severity'] ?? '';

        $result = [];
        foreach ($vulns as $v) {
            if ($category && $v['category'] !== $category) continue;
            if ($severity && $v['severity'] !== $severity) continue;
            $result[] = [
                'id' => $v['id'],
                'name' => $v['name'],
                'category' => $v['category'],
                'severity' => $v['severity'],
                'owasp' => $v['owasp'],
                'cwe' => $v['cwe'],
                'description' => $v['description'],
            ];
        }

        echo json_encode($result);
    }

    public static function vulnerability(string $id): void
    {
        if (Config::getMode() !== 'documentation') {
            http_response_code(403);
            echo json_encode([
                'error' => 'Documentation mode is disabled',
                'message' => 'Set DOJO_MODE=documentation to access vulnerability details',
                'current_mode' => Config::getMode(),
            ]);
            return;
        }

        $vulns = self::loadVulnerabilities();
        foreach ($vulns as $v) {
            if ($v['id'] === $id) {
                echo json_encode($v);
                return;
            }
        }

        http_response_code(404);
        echo json_encode(['detail' => "Vulnerability $id not found"]);
    }

    private static function getKeyDifferences(): array
    {
        return [
            'V01' => 'Add authorization check: verify user owns the resource or has admin role',
            'V02' => 'Use strong secrets from environment + generic error messages',
            'V03' => 'Use response models (DTOs) to filter sensitive fields',
            'V04' => 'Implement rate limiting with sliding window or token bucket',
            'V05' => 'Whitelist allowed fields, never bind request directly to model',
            'V06' => 'Use parameterized queries, never concatenate user input into SQL',
            'V07' => 'Validate input strictly, use safe APIs instead of shell execution',
            'V08' => 'Configure CORS properly, disable debug endpoints in production',
            'V09' => 'Deprecate and remove old API versions, apply same security controls',
            'V10' => 'Log security events, implement alerting on suspicious patterns',
            'G01' => 'Disable introspection in production',
            'G02' => 'Set query depth limit: max_depth=10',
            'G03' => 'Limit batch size and implement query cost analysis',
            'G04' => 'Disable field suggestions in production errors',
            'G05' => 'Add authorization checks to all resolvers',
        ];
    }

    public static function compareList(): void
    {
        $vulns = self::loadVulnerabilities();
        $keyDiffs = self::getKeyDifferences();
        $result = [];

        foreach ($vulns as $v) {
            $result[] = [
                'id' => $v['id'],
                'name' => $v['name'],
                'key_difference' => $keyDiffs[$v['id']] ?? '',
            ];
        }

        echo json_encode($result);
    }

    public static function compare(string $id): void
    {
        $vulns = self::loadVulnerabilities();
        $keyDiffs = self::getKeyDifferences();

        foreach ($vulns as $v) {
            if ($v['id'] === $id) {
                echo json_encode([
                    'id' => $v['id'],
                    'name' => $v['name'],
                    'vulnerable_code' => $v['vulnerable_code'],
                    'secure_code' => $v['secure_code'],
                    'key_difference' => $keyDiffs[$id] ?? 'See secure_code for the fix',
                    'remediation' => $v['remediation'],
                    'owasp' => $v['owasp'],
                    'cwe' => $v['cwe'],
                ]);
                return;
            }
        }

        http_response_code(404);
        echo json_encode(['detail' => "Vulnerability $id not found"]);
    }

    private static function loadVulnerabilities(): array
    {
        $path = dirname(__DIR__, 2) . '/vulnerabilities.json';
        if (!file_exists($path)) return [];
        $data = json_decode(file_get_contents($path), true);
        return $data['vulnerabilities'] ?? [];
    }
}
