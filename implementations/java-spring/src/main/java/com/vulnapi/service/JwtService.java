package com.vulnapi.service;

import com.vulnapi.config.SecurityConfig;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Map;

/**
 * JWT Service for token creation and validation.
 */
@Service
public class JwtService {

    private final JdbcTemplate jdbc;

    public JwtService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public String createToken(Map<String, Object> user) {
        return Jwts.builder()
            .claim("sub", user.get("username"))
            .claim("user_id", user.get("id"))
            .claim("role", user.get("role"))
            .expiration(new Date(System.currentTimeMillis() + 86400000))
            .signWith(SecurityConfig.SECRET_KEY)
            .compact();
    }

    public Map<String, Object> parseToken(String token) {
        try {
            var claims = Jwts.parser()
                .verifyWith(SecurityConfig.SECRET_KEY)
                .build()
                .parseSignedClaims(token)
                .getPayload();
            return Map.of("user_id", claims.get("user_id"), "role", claims.get("role"));
        } catch (Exception e) {
            return null;
        }
    }

    public Map<String, Object> getAuthUser(HttpServletRequest request) {
        String auth = request.getHeader("Authorization");
        if (auth == null || !auth.startsWith("Bearer ")) return null;

        var payload = parseToken(auth.substring(7));
        if (payload == null) return null;

        return jdbc.queryForMap("SELECT * FROM users WHERE id = ?", payload.get("user_id"));
    }
}
