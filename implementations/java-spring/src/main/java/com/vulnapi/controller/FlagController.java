package com.vulnapi.controller;

import com.vulnapi.service.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Challenge and flag submission endpoints.
 */
@RestController
@RequestMapping("/api")
public class FlagController {

    private final JdbcTemplate jdbc;
    private final JwtService jwtService;

    public FlagController(JdbcTemplate jdbc, JwtService jwtService) {
        this.jdbc = jdbc;
        this.jwtService = jwtService;
    }

    @GetMapping("/challenges")
    public List<Map<String, Object>> listChallenges() {
        var flags = jdbc.queryForList("SELECT challenge_id, description FROM flags");
        return flags.stream().map(f -> Map.<String, Object>of(
            "id", f.get("challenge_id"),
            "description", f.get("description"),
            "category", ((String)f.get("challenge_id")).startsWith("G") ? "graphql" : "rest"
        )).toList();
    }

    @PostMapping("/flags/submit")
    public ResponseEntity<?> submitFlag(@RequestBody Map<String, String> body, HttpServletRequest request) {
        if (jwtService.getAuthUser(request) == null) {
            return ResponseEntity.status(401).body(Map.of("detail", "Not authenticated"));
        }

        try {
            var flag = jdbc.queryForMap("SELECT * FROM flags WHERE flag_value = ?", body.get("flag"));
            return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "Congratulations! You solved challenge " + flag.get("challenge_id") + "!",
                "challenge_id", flag.get("challenge_id")
            ));
        } catch (Exception e) {
            return ResponseEntity.ok(Map.of("success", false, "message", "Invalid flag"));
        }
    }
}
