package com.vulnapi.config;

import io.jsonwebtoken.security.Keys;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

/**
 * Security Configuration.
 * VULNERABILITY V02: Weak secret key and weak password hashing.
 */
@Configuration
public class SecurityConfig {

    // VULNERABILITY V02: Weak secret key (predictable, short)
    public static final String JWT_SECRET = "secret123secret123secret123secret123";
    public static final SecretKey SECRET_KEY = Keys.hmacShaKeyFor(JWT_SECRET.getBytes(StandardCharsets.UTF_8));

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        // VULNERABILITY V02: Weak cost factor (should be 10-12)
        return new BCryptPasswordEncoder(4);
    }
}
