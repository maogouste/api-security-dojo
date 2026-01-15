package com.vulnapi.graphql;

import graphql.ExecutionInput;
import graphql.ExecutionResult;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

/**
 * GraphQL endpoint controller.
 *
 * VULNERABILITIES:
 * - G03: Batching enabled without limits
 * - G04: Detailed error messages with field suggestions
 */
@RestController
public class GraphQLController {

    private final GraphQLConfig graphQLConfig;

    public GraphQLController(GraphQLConfig graphQLConfig) {
        this.graphQLConfig = graphQLConfig;
    }

    @RequestMapping(value = {"/graphql", "/graphql/"}, method = {RequestMethod.GET, RequestMethod.POST})
    public ResponseEntity<?> graphql(
            @RequestBody(required = false) Object body,
            @RequestParam(required = false) String query) {

        // VULNERABILITY G03: Process batched queries without any limits
        if (body instanceof List<?> batchedQueries) {
            List<Map<String, Object>> results = new ArrayList<>();
            for (Object q : batchedQueries) {
                @SuppressWarnings("unchecked")
                Map<String, Object> queryMap = (Map<String, Object>) q;
                results.add(executeGraphQL((String) queryMap.get("query"), queryMap.get("variables")));
            }
            return ResponseEntity.ok(results);
        }

        // Single query
        String q = query;
        Object variables = null;
        if (body instanceof Map<?, ?> bodyMap) {
            if (q == null) q = (String) bodyMap.get("query");
            variables = bodyMap.get("variables");
        }

        if (q == null) {
            return ResponseEntity.ok(Map.of("data", null, "errors", List.of(Map.of("message", "No query provided"))));
        }

        return ResponseEntity.ok(executeGraphQL(q, variables));
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> executeGraphQL(String query, Object variables) {
        ExecutionInput.Builder inputBuilder = ExecutionInput.newExecutionInput().query(query);
        if (variables instanceof Map) {
            inputBuilder.variables((Map<String, Object>) variables);
        }

        ExecutionResult result = graphQLConfig.getGraphQL().execute(inputBuilder.build());
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("data", result.getData());
        if (!result.getErrors().isEmpty()) {
            // VULNERABILITY G04: Include detailed error messages with field suggestions
            response.put("errors", result.getErrors().stream().map(e -> Map.of(
                "message", e.getMessage(),
                "locations", e.getLocations() != null ? e.getLocations() : List.of(),
                "path", e.getPath() != null ? e.getPath() : List.of()
            )).toList());
        }
        return response;
    }
}
