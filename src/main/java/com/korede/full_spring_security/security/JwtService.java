package com.korede.full_spring_security.security;

import com.korede.full_spring_security.config.FullSecurityProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;

/**
 * Verification only - this library holds a public key and never signs.
 *
 * The parser is built once and reused. Verifying a token is a single parse:
 * signature, expiry, issuer and audience are all checked by that one call.
 */
@RequiredArgsConstructor
public class JwtService {

    private final FullSecurityProperties properties;

    private volatile JwtParser parser;

    /**
     * Verifies signature, expiry and any configured issuer/audience, and
     * returns the claims. Throws if the token is not valid for this service.
     */
    public Claims parseClaims(String token) {
        return parser().parseSignedClaims(token).getPayload();
    }

    public String extractUsername(String token) {
        return parseClaims(token).getSubject();
    }

    /**
     * Roles carried by the token, from the configured role claim. Accepts a
     * single string or an array; returns empty when the claim is absent.
     */
    public List<String> extractRoles(String token) {
        return extractRoles(parseClaims(token));
    }

    public List<String> extractRoles(Claims claims) {

        Object raw = claims.get(properties.getClient().getRoleClaim());

        if (raw == null) {
            return List.of();
        }

        if (raw instanceof Collection<?> values) {
            return values.stream()
                    .filter(Objects::nonNull)
                    .map(Object::toString)
                    .filter(value -> !value.isBlank())
                    .toList();
        }

        String value = raw.toString();

        return value.isBlank() ? List.of() : List.of(value);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        return claimsResolver.apply(parseClaims(token));
    }

    /** True when the token verifies and its subject matches. */
    public boolean isTokenValid(String token, String username) {

        try {
            return Objects.equals(username, parseClaims(token).getSubject());

        } catch (Exception e) {
            return false;
        }
    }

    public boolean isSignatureValid(String token) {

        try {
            parseClaims(token);
            return true;

        } catch (Exception e) {
            return false;
        }
    }

    private JwtParser parser() {

        JwtParser existing = this.parser;

        if (existing != null) {
            return existing;
        }

        synchronized (this) {

            if (this.parser == null) {

                FullSecurityProperties.Client client = properties.getClient();

                JwtParserBuilder builder = Jwts.parser()
                        .verifyWith(publicKey())
                        .clockSkewSeconds(client.getClockSkewSeconds());

                if (client.getIssuer() != null && !client.getIssuer().isBlank()) {
                    builder.requireIssuer(client.getIssuer());
                }

                if (client.getAudience() != null && !client.getAudience().isBlank()) {
                    builder.requireAudience(client.getAudience());
                }

                this.parser = builder.build();
            }

            return this.parser;
        }
    }

    private PublicKey publicKey() {

        String publicKey = properties.getClient().getPublicKey();

        if (publicKey == null || publicKey.isBlank()) {
            throw new IllegalStateException(
                    "full-security.client.public-key is not set. Provide the "
                    + "Base64-encoded X.509 RSA public key used to verify "
                    + "incoming JWTs, for example:\n\n"
                    + "  full-security.client.public-key=${JWT_PUBLIC_KEY}\n");
        }

        try {

            byte[] keyBytes = Base64.getDecoder().decode(publicKey);

            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);

            return KeyFactory.getInstance("RSA").generatePublic(spec);

        } catch (Exception e) {
            throw new IllegalStateException("Unable to load JWT public key", e);
        }
    }
}
