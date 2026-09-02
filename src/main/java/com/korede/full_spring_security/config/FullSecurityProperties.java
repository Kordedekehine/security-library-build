package com.korede.full_spring_security.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@Data
@ConfigurationProperties(prefix = "full-security")
public class FullSecurityProperties {

    /** Ant patterns permitted without authentication. */
    private List<String> publicEndpoints = new ArrayList<>();

    private Client client = new Client();

    private Cors cors = new Cors();

    @Data
    public static class Client {

        /** Base64-encoded X.509 RSA public key used to verify incoming JWTs. */
        private String publicKey;

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
}
