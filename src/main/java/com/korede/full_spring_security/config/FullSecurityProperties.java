package com.korede.full_spring_security.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

@Data
@ConfigurationProperties(prefix = "full-security")
public class FullSecurityProperties {

    /** Ant patterns permitted without authentication. */
    private List<String> publicEndpoints = new ArrayList<>();

    private Client client = new Client();

    private Cors cors = new Cors();

    private Service service = new Service();

    /** Ordered role rules, evaluated after public endpoints. First match wins. */
    private List<Rule> rules = new ArrayList<>();

    private Swagger swagger = new Swagger();

    private Actuator actuator = new Actuator();

    @Data
    public static class Client {

        /**
         * Base64 X.509 public key used to verify incoming JWTs. RSA, EC and
         * EdDSA are all supported; PEM armour and whitespace are tolerated.
         * Ignored when jwks-uri is set.
         */
        private String publicKey;

        /** Optional hint: RSA, EC or EdDSA. Detected from the key when unset. */
        private String keyAlgorithm;

        /**
         * JWKS endpoint to resolve verification keys from, selecting by the
         * token's "kid". Takes precedence over public-key and is how key
         * rotation is picked up without a redeploy.
         */
        private String jwksUri;

        /** How long a fetched key set is trusted before refetching. */
        private Duration jwksCacheTtl = Duration.ofMinutes(15);

        /** Floor between refreshes triggered by an unrecognised kid. */
        private Duration jwksRefreshCooldown = Duration.ofSeconds(30);

        /** Connect timeout for the JWKS endpoint. */
        private Duration jwksTimeout = Duration.ofSeconds(5);

        /** If set, tokens must carry this "iss" claim. */
        private String issuer;

        /** If set, tokens must carry this "aud" claim. */
        private String audience;

        /** Tolerance for clock drift between issuer and this service. */
        private long clockSkewSeconds = 60;

        /** Claim carrying the caller's role(s). String or array. */
        private String roleClaim = "role";
    }

    @Data
    public static class Cors {

        private boolean enabled = false;

        private List<String> allowedOrigins = new ArrayList<>();

        private List<String> allowedMethods =
                new ArrayList<>(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));

        private List<String> allowedHeaders = new ArrayList<>(List.of("*"));

        private boolean allowCredentials = false;

        private long maxAgeSeconds = 3600;
    }

    /**
     * One authorization rule. Exactly one outcome must be chosen: permit-all,
     * a role list, or plain authenticated.
     */
    @Data
    public static class Rule {

        /** Ant pattern, e.g. /api/v1/admin/**. Required. */
        private String pattern;

        /** Caller needs any one of these. ROLE_ prefix optional. */
        private List<String> roles = new ArrayList<>();

        /** Limit the rule to these HTTP methods. Empty means all. */
        private List<String> methods = new ArrayList<>();

        /** Open this pattern to everyone. */
        private boolean permitAll = false;

        /** Require a valid token but no particular role. */
        private boolean authenticated = false;
    }

    @Data
    public static class Swagger {

        private boolean enabled = false;

        /** springdoc/OpenAPI surfaces opened when enabled. */
        private List<String> paths = new ArrayList<>(List.of(
                "/swagger-ui.html",
                "/swagger-ui/**",
                "/v3/api-docs",
                "/v3/api-docs/**",
                "/swagger-resources/**",
                "/webjars/**"));
    }

    @Data
    public static class Actuator {

        /** Endpoint ids reachable without a token, e.g. health, info. */
        private List<String> publicEndpoints = new ArrayList<>();

        /** Roles required for every other /actuator/** endpoint. */
        private List<String> roles = new ArrayList<>();
    }

    /**
     * Service-to-service authentication for SERVICE mode: a shared key sent
     * in a header, mapped to a named caller and its roles.
     */
    @Data
    public static class Service {

        /** Header carrying the shared key. */
        private String header = "X-API-Key";

        private List<Caller> callers = new ArrayList<>();
    }

    @Data
    public static class Caller {

        /** Name of the calling service. Becomes the authenticated principal. */
        private String id;

        /** Shared secret. Supply from the environment, never in a committed file. */
        private String key;

        /** Roles granted to this caller. ROLE_ prefix optional. */
        private List<String> roles = new ArrayList<>();
    }
}
