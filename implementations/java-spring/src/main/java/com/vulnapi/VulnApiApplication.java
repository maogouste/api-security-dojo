package com.vulnapi;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * VulnAPI - Spring Boot Implementation
 *
 * WARNING: This API contains intentional security vulnerabilities.
 * Do NOT deploy in production.
 *
 * This is the main entry point. All endpoints are organized in:
 * - controller/ - REST API controllers
 * - graphql/ - GraphQL schema and controller
 * - service/ - Business logic services
 * - config/ - Configuration classes
 */
@SpringBootApplication
public class VulnApiApplication {

    public static void main(String[] args) {
        checkProductionEnvironment();
        SpringApplication.run(VulnApiApplication.class, args);
    }

    /**
     * Check if running in a production-like environment and block startup.
     * This application is INTENTIONALLY VULNERABLE and should NEVER
     * be deployed in production environments.
     */
    private static void checkProductionEnvironment() {
        Map<String, String> indicators = new LinkedHashMap<>();

        addIfPresent(indicators, "PRODUCTION", System.getenv("PRODUCTION"));
        addIfPresent(indicators, "PROD", System.getenv("PROD"));
        if ("production".equals(System.getenv("NODE_ENV"))) {
            indicators.put("NODE_ENV=production", "true");
        }
        if ("production".equals(System.getenv("ENVIRONMENT"))) {
            indicators.put("ENVIRONMENT=production", "true");
        }
        addIfPresent(indicators, "AWS_EXECUTION_ENV", System.getenv("AWS_EXECUTION_ENV"));
        addIfPresent(indicators, "AWS_LAMBDA_FUNCTION_NAME", System.getenv("AWS_LAMBDA_FUNCTION_NAME"));
        addIfPresent(indicators, "KUBERNETES_SERVICE_HOST", System.getenv("KUBERNETES_SERVICE_HOST"));
        addIfPresent(indicators, "ECS_CONTAINER_METADATA_URI", System.getenv("ECS_CONTAINER_METADATA_URI"));
        addIfPresent(indicators, "GOOGLE_CLOUD_PROJECT", System.getenv("GOOGLE_CLOUD_PROJECT"));
        addIfPresent(indicators, "HEROKU_APP_NAME", System.getenv("HEROKU_APP_NAME"));
        addIfPresent(indicators, "VERCEL", System.getenv("VERCEL"));
        addIfPresent(indicators, "RENDER", System.getenv("RENDER"));

        if (!indicators.isEmpty()) {
            System.err.println("""

================================================================================
                    CRITICAL SECURITY WARNING
================================================================================

  API Security Dojo has detected a PRODUCTION-LIKE environment!

  Detected indicators:""");
            indicators.forEach((k, v) -> System.err.println("    - " + k + ": " + v));
            System.err.println("""

  THIS APPLICATION IS INTENTIONALLY VULNERABLE!
  It contains security vulnerabilities by design for educational purposes.

  DO NOT DEPLOY IN PRODUCTION - You WILL be compromised!

================================================================================
""");

            if (!"true".equals(System.getenv("DOJO_FORCE_START"))) {
                System.err.println("  To override this safety check (NOT RECOMMENDED), set:");
                System.err.println("    DOJO_FORCE_START=true\n");
                System.exit(1);
            } else {
                System.err.println("  WARNING: DOJO_FORCE_START=true detected.");
                System.err.println("  Proceeding despite production environment detection.");
                System.err.println("  YOU HAVE BEEN WARNED!\n");
            }
        }
    }

    private static void addIfPresent(Map<String, String> map, String key, String value) {
        if (value != null && !value.isEmpty()) {
            map.put(key, value);
        }
    }
}
