package com.korede.full_spring_security.security;

import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * The verified contents of a JWT.
 *
 * This is the library's own type on purpose. Returning the JWT library's
 * claim type here would make every consumer depend on it, so upgrading it
 * underneath would be a breaking change for them.
 */
public final class TokenClaims {

    private final Map<String, Object> claims;

    TokenClaims(Map<String, Object> claims) {
        this.claims = Collections.unmodifiableMap(
                new LinkedHashMap<>(Objects.requireNonNullElseGet(claims, Map::of)));
    }

    /** The "sub" claim - who the token is about. */
    public String subject() {
        return string("sub");
    }

    /** The "iss" claim - who minted the token. */
    public String issuer() {
        return string("iss");
    }

    /** The "jti" claim - the token's unique id, when present. */
    public String id() {
        return string("jti");
    }

    /** The "aud" claim. Empty when absent; a single audience yields one entry. */
    public Set<String> audience() {

        Object raw = claims.get("aud");

        if (raw == null) {
            return Set.of();
        }

        if (raw instanceof Collection<?> values) {

            Set<String> audience = new LinkedHashSet<>();

            values.stream()
                    .filter(Objects::nonNull)
                    .map(Object::toString)
                    .forEach(audience::add);

            return Collections.unmodifiableSet(audience);
        }

        return Set.of(raw.toString());
    }

    /** The "exp" claim, or null when the token does not carry one. */
    public Instant expiresAt() {
        return instant("exp");
    }

    /** The "iat" claim, or null when the token does not carry one. */
    public Instant issuedAt() {
        return instant("iat");
    }

    /** Any claim by name, or null when absent. */
    public Object claim(String name) {
        return claims.get(name);
    }

    /**
     * Any claim by name, cast to the given type.
     *
     * @throws IllegalArgumentException when the claim is present but is not
     *         of the requested type
     */
    public <T> T claim(String name, Class<T> type) {

        Object value = claims.get(name);

        if (value == null) {
            return null;
        }

        if (!type.isInstance(value)) {
            throw new IllegalArgumentException(
                    "Claim '" + name + "' is a " + value.getClass().getSimpleName()
                    + ", not a " + type.getSimpleName());
        }

        return type.cast(value);
    }

    /** Every claim, unmodifiable. */
    public Map<String, Object> asMap() {
        return claims;
    }

    private String string(String name) {

        Object value = claims.get(name);

        return value == null ? null : value.toString();
    }

    private Instant instant(String name) {

        Object value = claims.get(name);

        if (value == null) {
            return null;
        }

        if (value instanceof Date date) {
            return date.toInstant();
        }

        if (value instanceof Number seconds) {
            return Instant.ofEpochSecond(seconds.longValue());
        }

        return null;
    }

    @Override
    public String toString() {
        return "TokenClaims{sub=" + subject() + ", iss=" + issuer()
                + ", exp=" + expiresAt() + "}";
    }
}
