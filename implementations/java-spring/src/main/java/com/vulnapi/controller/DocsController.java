package com.vulnapi.controller;

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

    @Value("${vulnapi.mode:challenge}")
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
                "message", "Set VULNAPI_MODE=documentation to access vulnerability details",
                "current_mode", mode
            ));
        }

        return loadVulnerabilities().stream()
            .filter(v -> id.equals(v.get("id")))
            .findFirst()
            .map(ResponseEntity::ok)
            .orElse(ResponseEntity.status(404).body(Map.of("detail", "Vulnerability " + id + " not found")));
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
