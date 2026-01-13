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

    private static function loadVulnerabilities(): array
    {
        $path = dirname(__DIR__, 2) . '/vulnerabilities.json';
        if (!file_exists($path)) return [];
        $data = json_decode(file_get_contents($path), true);
        return $data['vulnerabilities'] ?? [];
    }
}
