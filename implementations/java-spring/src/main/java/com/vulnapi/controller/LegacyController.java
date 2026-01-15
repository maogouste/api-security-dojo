package com.vulnapi.controller;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Legacy API v1 endpoints.
 * VULNERABILITY V09: Improper Assets Management - Old API version still accessible.
 * Exposes password_hash and other sensitive fields.
 */
@RestController
@RequestMapping("/api/v1/users")
public class LegacyController {

    private final JdbcTemplate jdbc;

    public LegacyController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping
    public List<Map<String, Object>> listUsersV1() {
        // VULNERABILITY V09: Exposes password_hash!
        return jdbc.queryForList("SELECT * FROM users");
    }

    @GetMapping("/{id}")
    public Map<String, Object> getUserV1(@PathVariable int id) {
        // VULNERABILITY V09: Exposes all fields including password_hash
        return jdbc.queryForMap("SELECT * FROM users WHERE id = ?", id);
    }
}
