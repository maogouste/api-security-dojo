package com.apisecuritydojo.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

/**
 * Documentation endpoints.
 */
@RestController
@RequestMapping("/api/docs")
public class DocsController {

    @Value("${dojo.mode:challenge}")
    private String mode;

    private final ObjectMapper mapper = new ObjectMapper();

    @GetMapping("/mode")
    public Map<String, Object> docsMode() {
        return Map.of(
            "mode", mode,
            "documentation_enabled", mode.equals("documentation"),
            "description", mode.equals("documentation")
                ? "Documentation mode: Full exploitation details and remediation"
                : "Challenge mode: Limited information, find vulnerabilities yourself"
        );
    }

    @GetMapping("/stats")
    public Map<String, Object> docsStats() {
        var vulns = loadVulnerabilities();
        Map<String, Integer> bySeverity = new HashMap<>();
        Map<String, Integer> byCategory = new HashMap<>();
        int restApi = 0, graphql = 0;

        for (var v : vulns) {
            bySeverity.merge((String)v.get("severity"), 1, Integer::sum);
            byCategory.merge((String)v.get("category"), 1, Integer::sum);
            if (((String)v.get("id")).startsWith("V")) restApi++;
            else graphql++;
        }

        return Map.of(
            "total", vulns.size(),
            "by_severity", bySeverity,
            "by_category", byCategory,
            "rest_api", restApi,
            "graphql", graphql
        );
    }

    @GetMapping("/categories")
    public List<Map<String, Object>> docsCategories() {
        var vulns = loadVulnerabilities();
        Map<String, Map<String, Object>> categories = new HashMap<>();

        for (var v : vulns) {
            String cat = (String) v.get("category");
            categories.computeIfAbsent(cat, k -> new HashMap<>(Map.of(
                "name", k,
                "count", 0,
                "vulnerabilities", new ArrayList<String>()
            )));
            categories.get(cat).put("count", (Integer)categories.get(cat).get("count") + 1);
            ((List<String>)categories.get(cat).get("vulnerabilities")).add((String)v.get("id"));
        }

        return new ArrayList<>(categories.values());
    }

    @GetMapping("/vulnerabilities")
    public List<Map<String, Object>> docsVulnerabilities(
            @RequestParam(required = false) String category,
            @RequestParam(required = false) String severity) {
        var vulns = loadVulnerabilities();
        return vulns.stream()
            .filter(v -> category == null || category.equals(v.get("category")))
            .filter(v -> severity == null || severity.equals(v.get("severity")))
            .map(v -> Map.<String, Object>of(
                "id", v.get("id"),
                "name", v.get("name"),
                "category", v.get("category"),
                "severity", v.get("severity"),
                "owasp", v.get("owasp"),
                "cwe", v.get("cwe"),
                "description", v.get("description")
            ))
            .toList();
    }

    @GetMapping("/vulnerabilities/{id}")
    public ResponseEntity<?> docsVulnerability(@PathVariable String id) {
        if (!mode.equals("documentation")) {
            return ResponseEntity.status(403).body(Map.of(
                "error", "Documentation mode is disabled",
                "message", "Set DOJO_MODE=documentation to access vulnerability details",
                "current_mode", mode
            ));
        }

        return loadVulnerabilities().stream()
            .filter(v -> id.equals(v.get("id")))
            .findFirst()
            .map(ResponseEntity::ok)
            .orElse(ResponseEntity.status(404).body(Map.of("detail", "Vulnerability " + id + " not found")));
    }

    // Key differences for each vulnerability (educational summaries)
    private static final Map<String, String> KEY_DIFFERENCES = Map.ofEntries(
        Map.entry("V01", "Add authorization check: verify user owns the resource or has admin role"),
        Map.entry("V02", "Use strong secrets from environment + generic error messages"),
        Map.entry("V03", "Use response models (DTOs) to filter sensitive fields"),
        Map.entry("V04", "Implement rate limiting with sliding window or token bucket"),
        Map.entry("V05", "Whitelist allowed fields, never bind request directly to model"),
        Map.entry("V06", "Use parameterized queries, never concatenate user input into SQL"),
        Map.entry("V07", "Validate input strictly, use safe APIs instead of shell execution"),
        Map.entry("V08", "Configure CORS properly, disable debug endpoints in production"),
        Map.entry("V09", "Deprecate and remove old API versions, apply same security controls"),
        Map.entry("V10", "Log security events, implement alerting on suspicious patterns"),
        Map.entry("G01", "Disable introspection in production"),
        Map.entry("G02", "Set query depth limit: max_depth=10"),
        Map.entry("G03", "Limit batch size and implement query cost analysis"),
        Map.entry("G04", "Disable field suggestions in production errors"),
        Map.entry("G05", "Add authorization checks to all resolvers")
    );

    /**
     * Compare vulnerable vs secure code.
     * Available in BOTH challenge and documentation modes.
     */
    @GetMapping("/compare/{id}")
    @SuppressWarnings("unchecked")
    public ResponseEntity<?> compareCode(@PathVariable String id) {
        return loadVulnerabilities().stream()
            .filter(v -> id.equals(v.get("id")))
            .findFirst()
            .map(v -> {
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("id", v.get("id"));
                result.put("name", v.get("name"));
                result.put("vulnerable_code", v.get("vulnerable_code"));
                result.put("secure_code", v.get("secure_code"));
                result.put("key_difference", KEY_DIFFERENCES.getOrDefault(id, "See secure_code for the fix"));
                result.put("remediation", v.get("remediation"));
                result.put("owasp", v.get("owasp"));
                result.put("cwe", v.get("cwe"));
                return ResponseEntity.ok(result);
            })
            .orElse(ResponseEntity.status(404).body(Map.of("detail", "Vulnerability " + id + " not found")));
    }

    /**
     * List all available code comparisons.
     */
    @GetMapping("/compare")
    public List<Map<String, Object>> listComparisons() {
        return loadVulnerabilities().stream()
            .map(v -> Map.<String, Object>of(
                "id", v.get("id"),
                "name", v.get("name"),
                "key_difference", KEY_DIFFERENCES.getOrDefault((String)v.get("id"), "")
            ))
            .toList();
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> loadVulnerabilities() {
        try {
            var is = getClass().getClassLoader().getResourceAsStream("vulnerabilities.json");
            if (is == null) return List.of();
            JsonNode root = mapper.readTree(is);
            List<Map<String, Object>> result = new ArrayList<>();
            for (JsonNode v : root.get("vulnerabilities")) {
                result.add(mapper.convertValue(v, Map.class));
            }
            return result;
        } catch (Exception e) {
            return List.of();
        }
    }
}
