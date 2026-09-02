package com.korede.full_spring_security.security;

import com.korede.full_spring_security.config.FullSecurityProperties;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtServiceTests {

    private static KeyPair keyPair;

    @BeforeAll
    static void generateKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
    }

    private FullSecurityProperties properties() {
        FullSecurityProperties properties = new FullSecurityProperties();
        properties.getClient().setPublicKey(
                Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        return properties;
    }

    private String token(Map<String, Object> claims, String issuer, String audience,
            long expiresInSeconds) {

        var builder = Jwts.builder()
                .subject("taiwo")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expiresInSeconds * 1000));

        claims.forEach(builder::claim);

        if (issuer != null) {
            builder.issuer(issuer);
        }

        if (audience != null) {
            builder.audience().add(audience).and();
        }

        return builder.signWith(keyPair.getPrivate()).compact();
    }

    @Test
    void readsSubjectAndSingleStringRole() {

        JwtService service = new JwtService(properties());

        String jwt = token(Map.of("role", "ADMIN"), null, null, 60);

        assertEquals("taiwo", service.extractUsername(jwt));
        assertEquals(List.of("ADMIN"), service.extractRoles(jwt));
    }

    @Test
    void readsRolesFromAnArrayClaim() {

        JwtService service = new JwtService(properties());

        String jwt = token(Map.of("role", List.of("ADMIN", "AUDITOR")), null, null, 60);

        assertEquals(List.of("ADMIN", "AUDITOR"), service.extractRoles(jwt));
    }

    @Test
    void returnsNoRolesWhenClaimAbsent() {

        JwtService service = new JwtService(properties());

        assertTrue(service.extractRoles(token(Map.of(), null, null, 60)).isEmpty());
    }

    @Test
    void honoursAConfiguredRoleClaimName() {

        FullSecurityProperties properties = properties();
        properties.getClient().setRoleClaim("authorities");

        JwtService service = new JwtService(properties);

        String jwt = token(Map.of("authorities", "TELLER"), null, null, 60);

        assertEquals(List.of("TELLER"), service.extractRoles(jwt));
    }

    @Test
    void rejectsAnExpiredToken() {

        JwtService service = new JwtService(properties());

        String jwt = token(Map.of(), null, null, -3600);

        assertFalse(service.isSignatureValid(jwt));
        assertThrows(Exception.class, () -> service.verify(jwt));
    }

    @Test
    void rejectsATokenFromTheWrongIssuer() {

        FullSecurityProperties properties = properties();
        properties.getClient().setIssuer("auth-service");

        JwtService service = new JwtService(properties);

        assertTrue(service.isSignatureValid(token(Map.of(), "auth-service", null, 60)));
        assertFalse(service.isSignatureValid(token(Map.of(), "someone-else", null, 60)));
    }

    @Test
    void rejectsATokenForTheWrongAudience() {

        FullSecurityProperties properties = properties();
        properties.getClient().setAudience("boilerplate");

        JwtService service = new JwtService(properties);

        assertTrue(service.isSignatureValid(token(Map.of(), null, "boilerplate", 60)));
        assertFalse(service.isSignatureValid(token(Map.of(), null, "other-service", 60)));
    }

    @Test
    void rejectsATokenSignedByAnotherKey() throws Exception {

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);

        String foreign = Jwts.builder()
                .subject("taiwo")
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(generator.generateKeyPair().getPrivate())
                .compact();

        assertFalse(new JwtService(properties()).isSignatureValid(foreign));
    }

    @Test
    void verifiesAnEllipticCurveToken() throws Exception {

        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        KeyPair ec = generator.generateKeyPair();

        FullSecurityProperties properties = new FullSecurityProperties();
        properties.getClient().setPublicKey(
                Base64.getEncoder().encodeToString(ec.getPublic().getEncoded()));

        String jwt = Jwts.builder()
                .subject("taiwo")
                .claim("role", "ADMIN")
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(ec.getPrivate())
                .compact();

        JwtService service = new JwtService(properties);

        assertEquals("taiwo", service.extractUsername(jwt));
        assertEquals(List.of("ADMIN"), service.extractRoles(jwt));
    }

    @Test
    void acceptsAKeyPastedWithPemArmourAndNewlines() {

        String raw = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());

        StringBuilder pem = new StringBuilder("-----BEGIN PUBLIC KEY-----\n");
        for (int i = 0; i < raw.length(); i += 64) {
            pem.append(raw, i, Math.min(i + 64, raw.length())).append('\n');
        }
        pem.append("-----END PUBLIC KEY-----\n");

        FullSecurityProperties properties = new FullSecurityProperties();
        properties.getClient().setPublicKey(pem.toString());

        JwtService service = new JwtService(properties);

        assertEquals("taiwo",
                service.extractUsername(token(Map.of(), null, null, 60)));
    }

    @Test
    void exposesClaimsWithoutTheJwtLibrarysTypes() {

        JwtService service = new JwtService(properties());

        TokenClaims claims = service.verify(
                token(Map.of("role", "ADMIN", "tenant", "acme"), "auth-service", "orders", 60));

        assertEquals("taiwo", claims.subject());
        assertEquals("auth-service", claims.issuer());
        assertTrue(claims.audience().contains("orders"));
        assertEquals("acme", claims.claim("tenant", String.class));
        assertTrue(claims.expiresAt().isAfter(java.time.Instant.now()));
        assertThrows(IllegalArgumentException.class,
                () -> claims.claim("tenant", Integer.class));
    }

    @Test
    void namesTheMissingKeyConfigurationWhenNeitherSourceIsSet() {

        JwtService service = new JwtService(new FullSecurityProperties());

        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> service.verify("any.token.here"));

        assertTrue(e.getMessage().contains("jwks-uri"));
        assertTrue(e.getMessage().contains("public-key"));
    }
}
