package com.korede.full_spring_security.security;

import com.korede.full_spring_security.config.FullSecurityProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;

import java.util.Collection;
import java.util.List;
import java.util.Objects;

/**
 * Verification only - this library holds public keys and never signs.
 *
 * The parser is built once and reused. Verifying a token is a single parse:
 * signature, expiry, issuer and audience are all checked by that one call.
 *
 * Keys come from either a static configured public key (RSA, EC or EdDSA) or
 * a JWKS endpoint, selected by the token's "kid".
 */
@RequiredArgsConstructor
public class JwtService {

    private final FullSecurityProperties properties;

    private volatile JwtParser parser;

    /**
     * Verifies signature, expiry and any configured issuer and audience.
     *
     * @throws RuntimeException when the token is not valid for this service
     */
    public TokenClaims verify(String token) {

        Claims claims = parser().parseSignedClaims(token).getPayload();

        return new TokenClaims(claims);
    }

    public String extractUsername(String token) {
        return verify(token).subject();
    }

    /**
     * Roles carried by the token, read from the configured role claim.
     * Accepts a single string or an array; empty when the claim is absent.
     */
    public List<String> extractRoles(String token) {
        return extractRoles(verify(token));
    }

    public List<String> extractRoles(TokenClaims claims) {

        Object raw = claims.claim(properties.getClient().getRoleClaim());

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

    /** True when the token verifies and its subject matches. */
    public boolean isTokenValid(String token, String username) {

        try {
            return Objects.equals(username, verify(token).subject());

        } catch (Exception e) {
            return false;
        }
    }

    public boolean isSignatureValid(String token) {

        try {
            verify(token);
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
                        .clockSkewSeconds(client.getClockSkewSeconds());

                applyKeySource(builder, client);

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

    private void applyKeySource(JwtParserBuilder builder,
            FullSecurityProperties.Client client) {

        boolean hasJwks = client.getJwksUri() != null && !client.getJwksUri().isBlank();
        boolean hasStatic = client.getPublicKey() != null && !client.getPublicKey().isBlank();

        if (hasJwks) {
            builder.keyLocator(new JwksKeyLocator(
                    client.getJwksUri(),
                    client.getJwksCacheTtl(),
                    client.getJwksRefreshCooldown(),
                    client.getJwksTimeout()));
            return;
        }

        if (hasStatic) {
            builder.verifyWith(
                    VerificationKeys.parse(client.getPublicKey(), client.getKeyAlgorithm()));
            return;
        }

        throw new IllegalStateException(
                "No JWT verification key configured. Set one of:\n\n"
                + "  full-security.client.jwks-uri=https://issuer/.well-known/jwks.json\n"
                + "  full-security.client.public-key=${JWT_PUBLIC_KEY}\n");
    }
}
