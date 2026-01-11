package com.vulnapi;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import graphql.*;
import graphql.schema.*;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.crypto.SecretKey;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * VulnAPI - Spring Boot Implementation
 *
 * WARNING: This API contains intentional security vulnerabilities.
 * Do NOT deploy in production.
 */
@SpringBootApplication
@RestController
public class VulnApiApplication {

    // VULNERABILITY V02: Weak secret key
    private static final String JWT_SECRET = "secret123secret123secret123secret123";
    private static final SecretKey SECRET_KEY = Keys.hmacShaKeyFor(JWT_SECRET.getBytes(StandardCharsets.UTF_8));

    @Value("${vulnapi.mode:challenge}")
    private String mode;

    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper = new ObjectMapper();
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(4); // Weak cost
    private GraphQL graphQL;

    public VulnApiApplication(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public static void main(String[] args) {
        SpringApplication.run(VulnApiApplication.class, args);
    }

    @PostConstruct
    public void init() {
        initDatabase();
        initGraphQL();
        System.out.println("""

            ╔═══════════════════════════════════════════════════════════╗
            ║                                                           ║
            ║   VulnAPI - Java/Spring Boot Implementation               ║
            ║   ⚠️  WARNING: Intentionally Vulnerable API               ║
            ║                                                           ║
            ║   Server running on http://localhost:3004                 ║
            ║                                                           ║
            ╚═══════════════════════════════════════════════════════════╝
            """);
    }

    // VULNERABILITY V08: CORS misconfiguration
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedOrigins("*")
                        .allowedMethods("*")
                        .allowedHeaders("*");
            }
        };
    }

    // Database initialization
    private void initDatabase() {
        jdbc.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                is_active INTEGER DEFAULT 1,
                ssn TEXT,
                credit_card TEXT,
                secret_note TEXT,
                api_key TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """);
        jdbc.execute("""
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                price REAL NOT NULL,
                stock INTEGER DEFAULT 0,
                category TEXT,
                is_active INTEGER DEFAULT 1,
                internal_notes TEXT,
                supplier_cost REAL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """);
        jdbc.execute("""
            CREATE TABLE IF NOT EXISTS flags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                challenge_id TEXT UNIQUE NOT NULL,
                flag_value TEXT NOT NULL,
                description TEXT
            )
        """);

        Integer count = jdbc.queryForObject("SELECT COUNT(*) FROM users", Integer.class);
        if (count == 0) seedDatabase();
    }

    private void seedDatabase() {
        System.out.println("[*] Seeding database...");

        Object[][] users = {
            {"admin", "admin@vulnapi.local", "admin123", "admin", "123-45-6789", "4111-1111-1111-1111", "VULNAPI{bola_user_data_exposed}", "admin-api-key-12345"},
            {"john", "john@example.com", "password123", "user", "987-65-4321", "5500-0000-0000-0004", "John's private notes", null},
            {"jane", "jane@example.com", "jane2024", "user", "456-78-9012", "3400-0000-0000-009", "Jane's secret data", null},
            {"bob", "bob@example.com", "bob", "user", null, null, null, null},
            {"service_account", "service@vulnapi.local", "svc_password_2024", "superadmin", null, null, "Service account", "VULNAPI{jwt_weak_secret_cracked}"},
        };

        for (Object[] u : users) {
            jdbc.update("INSERT INTO users (username, email, password_hash, role, ssn, credit_card, secret_note, api_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                u[0], u[1], encoder.encode((String)u[2]), u[3], u[4], u[5], u[6], u[7]);
        }

        Object[][] products = {
            {"Laptop Pro X1", "High-performance laptop", 1299.99, 50, "Electronics", 1, "VULNAPI{exposure_internal_data_leak}", 850.00},
            {"Wireless Mouse", "Ergonomic wireless mouse", 49.99, 200, "Electronics", 1, "Supplier: TechCorp", 20.00},
            {"USB-C Hub", "7-in-1 USB-C hub", 79.99, 150, "Electronics", 1, "Best seller Q4 2024", 35.00},
            {"Mechanical Keyboard", "RGB mechanical keyboard", 149.99, 75, "Electronics", 1, null, 80.00},
            {"4K Monitor", "27-inch 4K IPS monitor", 399.99, 30, "Electronics", 1, "Discontinued", 250.00},
            {"Secret Product", "VULNAPI{sqli_database_dumped}", 9999.99, 1, "Hidden", 0, "Should never be visible", null},
        };

        for (Object[] p : products) {
            jdbc.update("INSERT INTO products (name, description, price, stock, category, is_active, internal_notes, supplier_cost) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
        }

        String[][] flags = {
            {"V01", "VULNAPI{bola_user_data_exposed}", "BOLA vulnerability"},
            {"V02", "VULNAPI{jwt_weak_secret_cracked}", "Weak JWT secret"},
            {"V03", "VULNAPI{exposure_internal_data_leak}", "Data exposure"},
            {"V04", "VULNAPI{ratelimit_bruteforce_success}", "No rate limiting"},
            {"V05", "VULNAPI{mass_assignment_privilege_escalation}", "Mass assignment"},
            {"V06", "VULNAPI{sqli_database_dumped}", "SQL injection"},
            {"V07", "VULNAPI{cmd_injection_rce_achieved}", "Command injection"},
            {"V08", "VULNAPI{misconfig_cors_headers_missing}", "Security misconfiguration"},
            {"V09", "VULNAPI{version_legacy_api_exposed}", "Legacy API exposed"},
            {"V10", "VULNAPI{logging_blind_attack_undetected}", "Insufficient logging"},
            {"G01", "VULNAPI{graphql_introspection_schema_leaked}", "GraphQL introspection"},
            {"G02", "VULNAPI{graphql_depth_resource_exhaustion}", "Query depth DoS"},
            {"G03", "VULNAPI{graphql_batch_rate_limit_bypass}", "Batching attacks"},
            {"G04", "VULNAPI{graphql_suggestions_field_enumeration}", "Field suggestions"},
            {"G05", "VULNAPI{graphql_authz_sensitive_data_exposed}", "Auth bypass"},
        };

        for (String[] f : flags) {
            jdbc.update("INSERT INTO flags (challenge_id, flag_value, description) VALUES (?, ?, ?)", f[0], f[1], f[2]);
        }

        System.out.println("[*] Database seeded successfully!");
    }

    // JWT helpers
    private String createToken(Map<String, Object> user) {
        return Jwts.builder()
            .claim("sub", user.get("username"))
            .claim("user_id", user.get("id"))
            .claim("role", user.get("role"))
            .expiration(new Date(System.currentTimeMillis() + 86400000))
            .signWith(SECRET_KEY)
            .compact();
    }

    private Map<String, Object> parseToken(String token) {
        try {
            var claims = Jwts.parser().verifyWith(SECRET_KEY).build().parseSignedClaims(token).getPayload();
            return Map.of("user_id", claims.get("user_id"), "role", claims.get("role"));
        } catch (Exception e) {
            return null;
        }
    }

    private Map<String, Object> getAuthUser(HttpServletRequest request) {
        String auth = request.getHeader("Authorization");
        if (auth == null || !auth.startsWith("Bearer ")) return null;

        var payload = parseToken(auth.substring(7));
        if (payload == null) return null;

        return jdbc.queryForMap("SELECT * FROM users WHERE id = ?", payload.get("user_id"));
    }

    // Root endpoints
    @GetMapping("/")
    public Map<String, Object> root() {
        return Map.of(
            "name", "VulnAPI",
            "version", "0.2.0",
            "mode", mode,
            "implementation", "Java/Spring Boot",
            "message", "Welcome to VulnAPI - A deliberately vulnerable API"
        );
    }

    @GetMapping("/health")
    public Map<String, Object> health() {
        return Map.of("status", "healthy", "implementation", "java-spring");
    }

    // Auth endpoints
    @PostMapping("/api/register")
    public ResponseEntity<?> register(@RequestBody Map<String, String> body) {
        String hash = encoder.encode(body.get("password"));
        try {
            jdbc.update("INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'user')",
                body.get("username"), body.get("email"), hash);
            return ResponseEntity.status(201).body(Map.of("username", body.get("username"), "email", body.get("email"), "role", "user"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("detail", "Username or email already exists"));
        }
    }

    @PostMapping("/api/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body) {
        try {
            var user = jdbc.queryForMap("SELECT * FROM users WHERE username = ?", body.get("username"));
            if (!encoder.matches(body.get("password"), (String) user.get("password_hash"))) {
                return ResponseEntity.status(401).body(Map.of("detail", "Incorrect password")); // VULNERABILITY: User enumeration
            }
            String token = createToken(user);
            return ResponseEntity.ok(Map.of("access_token", token, "token_type", "bearer", "user_id", user.get("id"), "role", user.get("role")));
        } catch (Exception e) {
            return ResponseEntity.status(401).body(Map.of("detail", "User not found")); // VULNERABILITY: User enumeration
        }
    }

    @GetMapping("/api/me")
    public ResponseEntity<?> me(HttpServletRequest request) {
        var user = getAuthUser(request);
        if (user == null) return ResponseEntity.status(401).body(Map.of("detail", "Not authenticated"));
        return ResponseEntity.ok(user);
    }

    // Users endpoints
    @GetMapping("/api/users")
    public List<Map<String, Object>> listUsers() {
        return jdbc.queryForList("SELECT * FROM users");
    }

    @GetMapping("/api/users/{id}")
    public ResponseEntity<?> getUser(@PathVariable int id) {
        // VULNERABILITY V01: No authorization check
        try {
            var user = jdbc.queryForMap("SELECT * FROM users WHERE id = ?", id);
            return ResponseEntity.ok(user);
        } catch (Exception e) {
            return ResponseEntity.status(404).body(Map.of("detail", "User not found"));
        }
    }

    @PutMapping("/api/users/{id}")
    public ResponseEntity<?> updateUser(@PathVariable int id, @RequestBody Map<String, Object> body, HttpServletRequest request) {
        if (getAuthUser(request) == null) return ResponseEntity.status(401).body(Map.of("detail", "Not authenticated"));

        // VULNERABILITY V05: Mass assignment
        for (var entry : body.entrySet()) {
            String field = entry.getKey();
            Object value = entry.getValue();
            if (field.equals("password")) {
                jdbc.update("UPDATE users SET password_hash = ? WHERE id = ?", encoder.encode((String)value), id);
            } else {
                // VULNERABLE: Direct SQL construction
                jdbc.update("UPDATE users SET " + field + " = ? WHERE id = ?", value, id);
            }
        }

        return ResponseEntity.ok(jdbc.queryForMap("SELECT * FROM users WHERE id = ?", id));
    }

    @DeleteMapping("/api/users/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable int id, HttpServletRequest request) {
        if (getAuthUser(request) == null) return ResponseEntity.status(401).body(Map.of("detail", "Not authenticated"));
        jdbc.update("DELETE FROM users WHERE id = ?", id);
        return ResponseEntity.ok(Map.of("message", "User deleted"));
    }

    // Legacy API - VULNERABILITY V09
    @GetMapping("/api/v1/users")
    public List<Map<String, Object>> listUsersV1() {
        return jdbc.queryForList("SELECT * FROM users"); // Exposes password_hash!
    }

    @GetMapping("/api/v1/users/{id}")
    public Map<String, Object> getUserV1(@PathVariable int id) {
        return jdbc.queryForMap("SELECT * FROM users WHERE id = ?", id);
    }

    // Products endpoints
    @GetMapping("/api/products")
    public Object listProducts(@RequestParam(required = false) String search) {
        if (search != null && !search.isEmpty()) {
            // VULNERABILITY V06: SQL Injection
            String query = "SELECT * FROM products WHERE name LIKE '%" + search + "%' OR description LIKE '%" + search + "%'";
            try {
                return jdbc.queryForList(query);
            } catch (Exception e) {
                return Map.of("error", e.getMessage(), "query", query);
            }
        }
        return jdbc.queryForList("SELECT * FROM products WHERE is_active = 1");
    }

    @GetMapping("/api/products/{id}")
    public Map<String, Object> getProduct(@PathVariable int id) {
        return jdbc.queryForMap("SELECT * FROM products WHERE id = ?", id);
    }

    // Tools endpoints
    @PostMapping("/api/tools/ping")
    public ResponseEntity<?> ping(@RequestBody Map<String, String> body, HttpServletRequest request) {
        if (getAuthUser(request) == null) return ResponseEntity.status(401).body(Map.of("detail", "Not authenticated"));

        String host = body.get("host");
        // VULNERABILITY V07: Command injection
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", "ping -c 1 " + host});
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) output.append(line).append("\n");
            return ResponseEntity.ok(Map.of("success", p.waitFor() == 0, "command", "ping -c 1 " + host, "output", output.toString()));
        } catch (Exception e) {
            return ResponseEntity.ok(Map.of("success", false, "error", e.getMessage()));
        }
    }

    @PostMapping("/api/tools/dns")
    public ResponseEntity<?> dns(@RequestBody Map<String, String> body, HttpServletRequest request) {
        if (getAuthUser(request) == null) return ResponseEntity.status(401).body(Map.of("detail", "Not authenticated"));

        String domain = body.get("domain");
        // VULNERABILITY V07: Command injection
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", "nslookup " + domain});
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) output.append(line).append("\n");
            return ResponseEntity.ok(Map.of("domain", domain, "output", output.toString()));
        } catch (Exception e) {
            return ResponseEntity.ok(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/api/tools/debug")
    public Map<String, Object> debug() {
        // VULNERABILITY V08: Exposes sensitive debug info
        return Map.of(
            "java_version", System.getProperty("java.version"),
            "env_vars", System.getenv(),
            "cwd", System.getProperty("user.dir")
        );
    }

    // Flags endpoints
    @GetMapping("/api/challenges")
    public List<Map<String, Object>> listChallenges() {
        var flags = jdbc.queryForList("SELECT challenge_id, description FROM flags");
        return flags.stream().map(f -> Map.<String, Object>of(
            "id", f.get("challenge_id"),
            "description", f.get("description"),
            "category", ((String)f.get("challenge_id")).startsWith("G") ? "graphql" : "rest"
        )).toList();
    }

    @PostMapping("/api/flags/submit")
    public ResponseEntity<?> submitFlag(@RequestBody Map<String, String> body, HttpServletRequest request) {
        if (getAuthUser(request) == null) return ResponseEntity.status(401).body(Map.of("detail", "Not authenticated"));

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

    // Docs endpoints
    @GetMapping("/api/docs/mode")
    public Map<String, Object> docsMode() {
        return Map.of(
            "mode", mode,
            "documentation_enabled", mode.equals("documentation"),
            "description", mode.equals("documentation")
                ? "Documentation mode: Full exploitation details and remediation"
                : "Challenge mode: Limited information, find vulnerabilities yourself"
        );
    }

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

    @GetMapping("/api/docs/stats")
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

        return Map.of("total", vulns.size(), "by_severity", bySeverity, "by_category", byCategory, "rest_api", restApi, "graphql", graphql);
    }

    @GetMapping("/api/docs/categories")
    public List<Map<String, Object>> docsCategories() {
        var vulns = loadVulnerabilities();
        Map<String, Map<String, Object>> categories = new HashMap<>();

        for (var v : vulns) {
            String cat = (String) v.get("category");
            categories.computeIfAbsent(cat, k -> new HashMap<>(Map.of("name", k, "count", 0, "vulnerabilities", new ArrayList<String>())));
            categories.get(cat).put("count", (Integer)categories.get(cat).get("count") + 1);
            ((List<String>)categories.get(cat).get("vulnerabilities")).add((String)v.get("id"));
        }

        return new ArrayList<>(categories.values());
    }

    @GetMapping("/api/docs/vulnerabilities")
    public List<Map<String, Object>> docsVulnerabilities(
            @RequestParam(required = false) String category,
            @RequestParam(required = false) String severity) {
        var vulns = loadVulnerabilities();
        return vulns.stream()
            .filter(v -> category == null || category.equals(v.get("category")))
            .filter(v -> severity == null || severity.equals(v.get("severity")))
            .map(v -> Map.<String, Object>of(
                "id", v.get("id"), "name", v.get("name"), "category", v.get("category"),
                "severity", v.get("severity"), "owasp", v.get("owasp"), "cwe", v.get("cwe"), "description", v.get("description")
            ))
            .toList();
    }

    @GetMapping("/api/docs/vulnerabilities/{id}")
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

    // GraphQL
    private void initGraphQL() {
        GraphQLObjectType userType = GraphQLObjectType.newObject()
            .name("User")
            .field(f -> f.name("id").type(Scalars.GraphQLInt))
            .field(f -> f.name("username").type(Scalars.GraphQLString))
            .field(f -> f.name("email").type(Scalars.GraphQLString))
            .field(f -> f.name("role").type(Scalars.GraphQLString))
            .field(f -> f.name("ssn").type(Scalars.GraphQLString))
            .field(f -> f.name("creditCard").type(Scalars.GraphQLString))
            .field(f -> f.name("secretNote").type(Scalars.GraphQLString))
            .field(f -> f.name("apiKey").type(Scalars.GraphQLString))
            .build();

        GraphQLObjectType productType = GraphQLObjectType.newObject()
            .name("Product")
            .field(f -> f.name("id").type(Scalars.GraphQLInt))
            .field(f -> f.name("name").type(Scalars.GraphQLString))
            .field(f -> f.name("description").type(Scalars.GraphQLString))
            .field(f -> f.name("price").type(Scalars.GraphQLFloat))
            .field(f -> f.name("internalNotes").type(Scalars.GraphQLString))
            .field(f -> f.name("supplierCost").type(Scalars.GraphQLFloat))
            .build();

        GraphQLObjectType queryType = GraphQLObjectType.newObject()
            .name("Query")
            .field(f -> f.name("users").type(GraphQLList.list(userType))
                .dataFetcher(env -> {
                    var rows = jdbc.queryForList("SELECT * FROM users");
                    return rows.stream().map(r -> {
                        Map<String, Object> m = new HashMap<>();
                        m.put("id", r.get("id")); m.put("username", r.get("username")); m.put("email", r.get("email"));
                        m.put("role", r.get("role")); m.put("ssn", r.get("ssn")); m.put("creditCard", r.get("credit_card"));
                        m.put("secretNote", r.get("secret_note")); m.put("apiKey", r.get("api_key"));
                        return m;
                    }).toList();
                }))
            .field(f -> f.name("products").type(GraphQLList.list(productType))
                .dataFetcher(env -> {
                    var rows = jdbc.queryForList("SELECT * FROM products");
                    return rows.stream().map(r -> {
                        Map<String, Object> m = new HashMap<>();
                        m.put("id", r.get("id")); m.put("name", r.get("name")); m.put("description", r.get("description"));
                        m.put("price", r.get("price")); m.put("internalNotes", r.get("internal_notes")); m.put("supplierCost", r.get("supplier_cost"));
                        return m;
                    }).toList();
                }))
            .build();

        GraphQLSchema schema = GraphQLSchema.newSchema().query(queryType).build();
        this.graphQL = GraphQL.newGraphQL(schema).build();
    }

    @RequestMapping(value = {"/graphql", "/graphql/"}, method = {RequestMethod.GET, RequestMethod.POST})
    public ResponseEntity<?> graphql(@RequestBody(required = false) Map<String, Object> body, @RequestParam(required = false) String query) {
        String q = query != null ? query : (body != null ? (String) body.get("query") : null);
        if (q == null) {
            return ResponseEntity.ok(Map.of("data", null, "errors", List.of(Map.of("message", "No query provided"))));
        }

        ExecutionResult result = graphQL.execute(q);
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("data", result.getData());
        if (!result.getErrors().isEmpty()) {
            response.put("errors", result.getErrors().stream().map(e -> Map.of("message", e.getMessage())).toList());
        }
        return ResponseEntity.ok(response);
    }
}
