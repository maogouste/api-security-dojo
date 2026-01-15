package com.vulnapi.graphql;

import com.vulnapi.service.JwtService;
import graphql.GraphQL;
import graphql.Scalars;
import graphql.schema.*;
import jakarta.annotation.PostConstruct;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * GraphQL Schema Configuration.
 *
 * VULNERABILITIES:
 * - G01: Introspection enabled (default in graphql-java)
 * - G02: No query depth limits (nested queries via User <-> Order)
 * - G03: Batching enabled without limits
 * - G04: Field suggestions enabled (default in graphql-java)
 * - G05: No authentication checks on sensitive queries
 */
@Component
public class GraphQLConfig {

    private final JdbcTemplate jdbc;
    private final BCryptPasswordEncoder encoder;
    private final JwtService jwtService;
    private GraphQL graphQL;

    public GraphQLConfig(JdbcTemplate jdbc, BCryptPasswordEncoder encoder, JwtService jwtService) {
        this.jdbc = jdbc;
        this.encoder = encoder;
        this.jwtService = jwtService;
    }

    @PostConstruct
    public void init() {
        initGraphQL();
    }

    public GraphQL getGraphQL() {
        return graphQL;
    }

    private void initGraphQL() {
        // Use GraphQLTypeReference for circular references (G02)
        GraphQLTypeReference userTypeRef = GraphQLTypeReference.typeRef("User");
        GraphQLTypeReference orderTypeRef = GraphQLTypeReference.typeRef("Order");

        // Order type - VULNERABILITY G02: Enables circular nesting back to User
        GraphQLObjectType orderType = GraphQLObjectType.newObject()
            .name("Order")
            .field(f -> f.name("id").type(Scalars.GraphQLInt))
            .field(f -> f.name("userId").type(Scalars.GraphQLInt))
            .field(f -> f.name("status").type(Scalars.GraphQLString))
            .field(f -> f.name("totalAmount").type(Scalars.GraphQLFloat))
            .field(f -> f.name("shippingAddress").type(Scalars.GraphQLString))
            .field(f -> f.name("notes").type(Scalars.GraphQLString))
            // G02: Circular reference to User
            .field(f -> f.name("user").type(userTypeRef)
                .dataFetcher(env -> {
                    Map<String, Object> order = env.getSource();
                    int userId = ((Number) order.get("userId")).intValue();
                    var r = jdbc.queryForMap("SELECT * FROM users WHERE id = ?", userId);
                    return mapUser(r);
                }))
            .build();

        // User type - VULNERABILITY G02, G05
        GraphQLObjectType userType = GraphQLObjectType.newObject()
            .name("User")
            .field(f -> f.name("id").type(Scalars.GraphQLInt))
            .field(f -> f.name("username").type(Scalars.GraphQLString))
            .field(f -> f.name("email").type(Scalars.GraphQLString))
            .field(f -> f.name("role").type(Scalars.GraphQLString))
            .field(f -> f.name("ssn").type(Scalars.GraphQLString))          // G05: Sensitive data
            .field(f -> f.name("creditCard").type(Scalars.GraphQLString))   // G05: Sensitive data
            .field(f -> f.name("secretNote").type(Scalars.GraphQLString))   // G05: Sensitive data
            .field(f -> f.name("apiKey").type(Scalars.GraphQLString))       // G05: Sensitive data
            // G02: Circular reference to Orders
            .field(f -> f.name("orders").type(GraphQLList.list(orderType))
                .dataFetcher(env -> {
                    Map<String, Object> user = env.getSource();
                    int userId = ((Number) user.get("id")).intValue();
                    var rows = jdbc.queryForList("SELECT * FROM orders WHERE user_id = ?", userId);
                    return rows.stream().map(this::mapOrder).toList();
                }))
            .build();

        // Product type - G05: Exposes internal data
        GraphQLObjectType productType = GraphQLObjectType.newObject()
            .name("Product")
            .field(f -> f.name("id").type(Scalars.GraphQLInt))
            .field(f -> f.name("name").type(Scalars.GraphQLString))
            .field(f -> f.name("description").type(Scalars.GraphQLString))
            .field(f -> f.name("price").type(Scalars.GraphQLFloat))
            .field(f -> f.name("internalNotes").type(Scalars.GraphQLString)) // G05: Internal data
            .field(f -> f.name("supplierCost").type(Scalars.GraphQLFloat))   // G05: Internal data
            .build();

        // Auth payload type
        GraphQLObjectType authPayloadType = GraphQLObjectType.newObject()
            .name("AuthPayload")
            .field(f -> f.name("accessToken").type(Scalars.GraphQLString))
            .field(f -> f.name("tokenType").type(Scalars.GraphQLString))
            .field(f -> f.name("userId").type(Scalars.GraphQLInt))
            .field(f -> f.name("role").type(Scalars.GraphQLString))
            .build();

        // Query type - G05: No auth checks on sensitive queries
        GraphQLObjectType queryType = GraphQLObjectType.newObject()
            .name("Query")
            .field(f -> f.name("users").type(GraphQLList.list(userType))
                .dataFetcher(env -> {
                    var rows = jdbc.queryForList("SELECT * FROM users");
                    return rows.stream().map(this::mapUser).toList();
                }))
            .field(f -> f.name("user").type(userType)
                .argument(a -> a.name("id").type(Scalars.GraphQLInt))
                .dataFetcher(env -> {
                    int id = env.getArgument("id");
                    var r = jdbc.queryForMap("SELECT * FROM users WHERE id = ?", id);
                    return mapUser(r);
                }))
            .field(f -> f.name("products").type(GraphQLList.list(productType))
                .dataFetcher(env -> {
                    var rows = jdbc.queryForList("SELECT * FROM products");
                    return rows.stream().map(this::mapProduct).toList();
                }))
            .field(f -> f.name("orders").type(GraphQLList.list(orderType))
                .dataFetcher(env -> {
                    var rows = jdbc.queryForList("SELECT * FROM orders");
                    return rows.stream().map(this::mapOrder).toList();
                }))
            .build();

        // Mutation type - G05: No proper auth checks
        GraphQLObjectType mutationType = GraphQLObjectType.newObject()
            .name("Mutation")
            .field(f -> f.name("login").type(authPayloadType)
                .argument(a -> a.name("username").type(Scalars.GraphQLString))
                .argument(a -> a.name("password").type(Scalars.GraphQLString))
                .dataFetcher(env -> {
                    String username = env.getArgument("username");
                    String password = env.getArgument("password");
                    try {
                        var user = jdbc.queryForMap("SELECT * FROM users WHERE username = ?", username);
                        if (encoder.matches(password, (String) user.get("password_hash"))) {
                            String token = jwtService.createToken(user);
                            return Map.of("accessToken", token, "tokenType", "bearer",
                                "userId", user.get("id"), "role", user.get("role"));
                        }
                    } catch (Exception ignored) {}
                    throw new RuntimeException("Invalid credentials");
                }))
            // G05: No authorization - anyone can update anyone
            .field(f -> f.name("updateUser").type(userType)
                .argument(a -> a.name("id").type(Scalars.GraphQLInt))
                .argument(a -> a.name("username").type(Scalars.GraphQLString))
                .argument(a -> a.name("email").type(Scalars.GraphQLString))
                .argument(a -> a.name("role").type(Scalars.GraphQLString)) // G05: Can escalate privileges!
                .dataFetcher(env -> {
                    int id = env.getArgument("id");
                    String role = env.getArgument("role");
                    String username = env.getArgument("username");
                    String email = env.getArgument("email");
                    if (role != null) jdbc.update("UPDATE users SET role = ? WHERE id = ?", role, id);
                    if (username != null) jdbc.update("UPDATE users SET username = ? WHERE id = ?", username, id);
                    if (email != null) jdbc.update("UPDATE users SET email = ? WHERE id = ?", email, id);
                    var r = jdbc.queryForMap("SELECT * FROM users WHERE id = ?", id);
                    return mapUser(r);
                }))
            .build();

        GraphQLSchema schema = GraphQLSchema.newSchema()
            .query(queryType)
            .mutation(mutationType)
            .build();
        this.graphQL = GraphQL.newGraphQL(schema).build();
    }

    private Map<String, Object> mapUser(Map<String, Object> r) {
        Map<String, Object> m = new HashMap<>();
        m.put("id", r.get("id"));
        m.put("username", r.get("username"));
        m.put("email", r.get("email"));
        m.put("role", r.get("role"));
        m.put("ssn", r.get("ssn"));
        m.put("creditCard", r.get("credit_card"));
        m.put("secretNote", r.get("secret_note"));
        m.put("apiKey", r.get("api_key"));
        return m;
    }

    private Map<String, Object> mapOrder(Map<String, Object> r) {
        Map<String, Object> m = new HashMap<>();
        m.put("id", r.get("id"));
        m.put("userId", r.get("user_id"));
        m.put("status", r.get("status"));
        m.put("totalAmount", r.get("total_amount"));
        m.put("shippingAddress", r.get("shipping_address"));
        m.put("notes", r.get("notes"));
        return m;
    }

    private Map<String, Object> mapProduct(Map<String, Object> r) {
        Map<String, Object> m = new HashMap<>();
        m.put("id", r.get("id"));
        m.put("name", r.get("name"));
        m.put("description", r.get("description"));
        m.put("price", r.get("price"));
        m.put("internalNotes", r.get("internal_notes"));
        m.put("supplierCost", r.get("supplier_cost"));
        return m;
    }
}
