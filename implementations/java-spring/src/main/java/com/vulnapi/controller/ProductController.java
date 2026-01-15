package com.vulnapi.controller;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Product endpoints.
 * VULNERABILITY V06: SQL Injection in search parameter.
 */
@RestController
@RequestMapping("/api/products")
public class ProductController {

    private final JdbcTemplate jdbc;

    public ProductController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping
    public Object listProducts(@RequestParam(required = false) String search) {
        if (search != null && !search.isEmpty()) {
            // VULNERABILITY V06: SQL Injection - Direct string concatenation
            String query = "SELECT * FROM products WHERE name LIKE '%" + search + "%' OR description LIKE '%" + search + "%'";
            try {
                return jdbc.queryForList(query);
            } catch (Exception e) {
                // VULNERABILITY V06: Returns SQL error details and query
                return Map.of("error", e.getMessage(), "query", query);
            }
        }
        return jdbc.queryForList("SELECT * FROM products WHERE is_active = 1");
    }

    @GetMapping("/{id}")
    public Map<String, Object> getProduct(@PathVariable int id) {
        return jdbc.queryForMap("SELECT * FROM products WHERE id = ?", id);
    }
}
