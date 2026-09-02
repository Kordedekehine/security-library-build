package com.korede.full_spring_security.security;

import io.jsonwebtoken.Header;
import io.jsonwebtoken.Locator;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.JwkSet;
import io.jsonwebtoken.security.Jwks;
import lombok.extern.slf4j.Slf4j;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.Key;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Resolves the verification key for a token from a JWKS endpoint, selecting
 * by the token's "kid" header.
 *
 * The key set is cached. An unknown kid triggers one refresh - that is how key
 * rotation is picked up without a redeploy - but refreshes are rate limited,
 * so a flood of tokens carrying junk kids cannot be used to hammer the
 * issuer through this service.
 */
@Slf4j
class JwksKeyLocator implements Locator<Key> {

    private final URI uri;

    private final Duration cacheTtl;

    private final Duration refreshCooldown;

    private final HttpClient http;

    private volatile Map<String, Key> keys = Map.of();

    private volatile Instant loadedAt = Instant.EPOCH;

    private volatile Instant lastAttempt = Instant.EPOCH;

    JwksKeyLocator(String uri, Duration cacheTtl,
            Duration refreshCooldown, Duration timeout) {

        this.uri = URI.create(uri);
        this.cacheTtl = cacheTtl;
        this.refreshCooldown = refreshCooldown;
        this.http = HttpClient.newBuilder()
                .connectTimeout(timeout)
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    @Override
    public Key locate(Header header) {

        Object kid = header.get("kid");

        if (kid == null) {
            throw new IllegalStateException(
                    "Token has no \"kid\" header, so no key can be selected from "
                    + uri + ". Either the issuer must set kid, or configure a "
                    + "static full-security.client.public-key instead.");
        }

        String keyId = kid.toString();

        if (isStale()) {
            refresh(false);
        }

        Key key = keys.get(keyId);

        if (key != null) {
            return key;
        }

        // Unknown kid usually means the issuer rotated. Try once more.
        refresh(true);

        key = keys.get(keyId);

        if (key == null) {
            throw new IllegalStateException(
                    "No key with kid '" + keyId + "' at " + uri
                    + ". Known kids: " + keys.keySet());
        }

        return key;
    }

    private boolean isStale() {
        return Instant.now().isAfter(loadedAt.plus(cacheTtl));
    }

    private synchronized void refresh(boolean rateLimited) {

        Instant now = Instant.now();

        if (rateLimited && now.isBefore(lastAttempt.plus(refreshCooldown))) {
            return;
        }

        lastAttempt = now;

        try {

            HttpRequest request = HttpRequest.newBuilder(uri)
                    .header("Accept", "application/json")
                    .GET()
                    .build();

            HttpResponse<String> response =
                    http.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                throw new IllegalStateException(
                        "JWKS endpoint returned HTTP " + response.statusCode());
            }

            JwkSet set = Jwks.setParser().build().parse(response.body());

            Map<String, Key> loaded = new LinkedHashMap<>();

            for (Jwk<?> jwk : set) {

                Object id = jwk.get("kid");

                if (id != null) {
                    loaded.put(id.toString(), jwk.toKey());
                }
            }

            this.keys = Map.copyOf(loaded);
            this.loadedAt = now;

            log.info("Loaded {} key(s) from JWKS {}", loaded.size(), uri);

        } catch (Exception e) {

            // Keep serving the cached set - an issuer blip should not take
            // every request down with it.
            log.warn("Could not refresh JWKS from {}: {}", uri, e.getMessage());

            if (keys.isEmpty()) {
                throw new IllegalStateException(
                        "Could not load JWKS from " + uri, e);
            }
        }
    }
}
