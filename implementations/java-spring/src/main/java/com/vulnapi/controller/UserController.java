package com.vulnapi.controller;

import com.vulnapi.service.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * User endpoints.
 * VULNERABILITIES:
 * - V01: Broken Object Level Authorization (BOLA)
 * - V03: Excessive Data Exposure
 * - V05: Mass Assignment
 */
@RestController
@RequestMapping("/api/users")
public class UserController {

    private final JdbcTemplate jdbc;
    private final BCryptPasswordEncoder encoder;
    private final JwtService jwtService;

    public UserController(JdbcTemplate jdbc, BCryptPasswordEncoder encoder, JwtService jwtService) {
        this.jdbc = jdbc;
        this.encoder = encoder;
        this.jwtService = jwtService;
    }

    @GetMapping
    public List<Map<String, Object>> listUsers() {
        // VULNERABILITY V03: Returns all fields including sensitive data
        return jdbc.queryForList("SELECT * FROM users");
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getUser(@PathVariable int id) {
        // VULNERABILITY V01: No authorization check - any user can access any user's data
        try {
            var user = jdbc.queryForMap("SELECT * FROM users WHERE id = ?", id);
            return ResponseEntity.ok(user);
        } catch (Exception e) {
            return ResponseEntity.status(404).body(Map.of("detail", "User not found"));
        }
    }

    @PutMapping("/{id}")
    public ResponseEntity<?> updateUser(@PathVariable int id, @RequestBody Map<String, Object> body, HttpServletRequest request) {
        if (jwtService.getAuthUser(request) == null) {
            return ResponseEntity.status(401).body(Map.of("detail", "Not authenticated"));
        }

        // VULNERABILITY V05: Mass assignment - allows updating any field including 'role'
        for (var entry : body.entrySet()) {
            String field = entry.getKey();
            Object value = entry.getValue();
            if (field.equals("password")) {
                jdbc.update("UPDATE users SET password_hash = ? WHERE id = ?", encoder.encode((String)value), id);
            } else {
                // VULNERABLE: Direct SQL construction allows updating any field
                jdbc.update("UPDATE users SET " + field + " = ? WHERE id = ?", value, id);
            }
        }

        return ResponseEntity.ok(jdbc.queryForMap("SELECT * FROM users WHERE id = ?", id));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable int id, HttpServletRequest request) {
        if (jwtService.getAuthUser(request) == null) {
            return ResponseEntity.status(401).body(Map.of("detail", "Not authenticated"));
        }
        jdbc.update("DELETE FROM users WHERE id = ?", id);
        return ResponseEntity.ok(Map.of("message", "User deleted"));
    }
}
