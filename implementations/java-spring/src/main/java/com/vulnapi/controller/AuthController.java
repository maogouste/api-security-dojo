package com.vulnapi.controller;

import com.vulnapi.service.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Authentication endpoints.
 * VULNERABILITY V02: User enumeration through different error messages.
 */
@RestController
@RequestMapping("/api")
public class AuthController {

    private final JdbcTemplate jdbc;
    private final BCryptPasswordEncoder encoder;
    private final JwtService jwtService;

    public AuthController(JdbcTemplate jdbc, BCryptPasswordEncoder encoder, JwtService jwtService) {
        this.jdbc = jdbc;
        this.encoder = encoder;
        this.jwtService = jwtService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String, String> body) {
        String hash = encoder.encode(body.get("password"));
        try {
            jdbc.update("INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'user')",
                body.get("username"), body.get("email"), hash);
            return ResponseEntity.status(201).body(Map.of(
                "username", body.get("username"),
                "email", body.get("email"),
                "role", "user"
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("detail", "Username or email already exists"));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body) {
        try {
            var user = jdbc.queryForMap("SELECT * FROM users WHERE username = ?", body.get("username"));
            if (!encoder.matches(body.get("password"), (String) user.get("password_hash"))) {
                // VULNERABILITY V02: Different error message reveals user exists
                return ResponseEntity.status(401).body(Map.of("detail", "Incorrect password"));
            }
            String token = jwtService.createToken(user);
            return ResponseEntity.ok(Map.of(
                "access_token", token,
                "token_type", "bearer",
                "user_id", user.get("id"),
                "role", user.get("role")
            ));
        } catch (Exception e) {
            // VULNERABILITY V02: Different error message reveals user doesn't exist
            return ResponseEntity.status(401).body(Map.of("detail", "User not found"));
        }
    }

    @GetMapping("/me")
    public ResponseEntity<?> me(HttpServletRequest request) {
        var user = jwtService.getAuthUser(request);
        if (user == null) {
            return ResponseEntity.status(401).body(Map.of("detail", "Not authenticated"));
        }
        return ResponseEntity.ok(user);
    }
}
