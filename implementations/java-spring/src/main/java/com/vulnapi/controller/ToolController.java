package com.vulnapi.controller;

import com.vulnapi.service.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Map;

/**
 * Tool endpoints (ping, dns, debug).
 * VULNERABILITIES:
 * - V07: Command Injection
 * - V08: Security Misconfiguration (debug endpoint exposes sensitive info)
 */
@RestController
@RequestMapping("/api/tools")
public class ToolController {

    private final JwtService jwtService;

    public ToolController(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @PostMapping("/ping")
    public ResponseEntity<?> ping(@RequestBody Map<String, String> body, HttpServletRequest request) {
        if (jwtService.getAuthUser(request) == null) {
            return ResponseEntity.status(401).body(Map.of("detail", "Not authenticated"));
        }

        String host = body.get("host");
        // VULNERABILITY V07: Command injection - User input passed directly to shell
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", "ping -c 1 " + host});
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            return ResponseEntity.ok(Map.of(
                "success", p.waitFor() == 0,
                "command", "ping -c 1 " + host,
                "output", output.toString()
            ));
        } catch (Exception e) {
            return ResponseEntity.ok(Map.of("success", false, "error", e.getMessage()));
        }
    }

    @PostMapping("/dns")
    public ResponseEntity<?> dns(@RequestBody Map<String, String> body, HttpServletRequest request) {
        if (jwtService.getAuthUser(request) == null) {
            return ResponseEntity.status(401).body(Map.of("detail", "Not authenticated"));
        }

        String domain = body.get("domain");
        // VULNERABILITY V07: Command injection
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", "nslookup " + domain});
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            return ResponseEntity.ok(Map.of("domain", domain, "output", output.toString()));
        } catch (Exception e) {
            return ResponseEntity.ok(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/debug")
    public Map<String, Object> debug() {
        // VULNERABILITY V08: Exposes sensitive debug information
        return Map.of(
            "java_version", System.getProperty("java.version"),
            "env_vars", System.getenv(),
            "cwd", System.getProperty("user.dir")
        );
    }
}
