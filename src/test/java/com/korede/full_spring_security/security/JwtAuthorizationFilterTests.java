package com.korede.full_spring_security.security;

import com.korede.full_spring_security.config.FullSecurityProperties;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

/**
 * SERVICE mode has no local user record for a calling service, so the token
 * is the whole of what is known about the caller.
 */
class JwtAuthorizationFilterTests {

    private static KeyPair keyPair;

    private final FullSecurityAuthenticationEntryPoint entryPoint =
            new FullSecurityAuthenticationEntryPoint();

    @BeforeAll
    static void generateKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
    }

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    private FullSecurityProperties properties() {
        FullSecurityProperties properties = new FullSecurityProperties();
        properties.getClient().setPublicKey(
                Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        return properties;
    }

    private String token(String subject, Object role) {

        var builder = Jwts.builder()
                .subject(subject)
                .expiration(new Date(System.currentTimeMillis() + 60_000));

        if (role != null) {
            builder.claim("role", role);
        }

        return builder.signWith(keyPair.getPrivate()).compact();
    }

    private Authentication run(JwtAuthorizationFilter filter, String jwt,
            MockHttpServletResponse response) throws Exception {

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + jwt);

        filter.doFilter(request, response, mock(FilterChain.class));

        return SecurityContextHolder.getContext().getAuthentication();
    }

    @Test
    void serviceModeTakesTheSubjectAsPrincipalAndRolesFromTheToken() throws Exception {

        JwtAuthorizationFilter filter = new JwtAuthorizationFilter(
                new JwtService(properties()), entryPoint);

        Authentication authentication = run(filter,
                token("orders-service", "ORDERS"), new MockHttpServletResponse());

        assertNotNull(authentication);
        assertEquals("orders-service", authentication.getName());
        assertEquals("orders-service", authentication.getPrincipal());
        assertTrue(authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ORDERS")));
    }

    @Test
    void serviceModeGrantsNothingWhenTheTokenCarriesNoRole() throws Exception {

        JwtAuthorizationFilter filter = new JwtAuthorizationFilter(
                new JwtService(properties()), entryPoint);

        Authentication authentication = run(filter,
                token("orders-service", null), new MockHttpServletResponse());

        assertNotNull(authentication);
        assertTrue(authentication.getAuthorities().isEmpty(),
                "no local record to fall back on, so a role-gated endpoint must 403");
    }

    @Test
    void serviceModeReadsSeveralRolesFromAnArrayClaim() throws Exception {

        JwtAuthorizationFilter filter = new JwtAuthorizationFilter(
                new JwtService(properties()), entryPoint);

        Authentication authentication = run(filter,
                token("billing-service", List.of("BILLING", "REPORTING")),
                new MockHttpServletResponse());

        assertEquals(2, authentication.getAuthorities().size());
        assertTrue(authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_BILLING")));
        assertTrue(authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_REPORTING")));
    }

    @Test
    void serviceModeRejectsATokenSignedByAnotherKey() throws Exception {

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);

        String foreign = Jwts.builder()
                .subject("attacker")
                .claim("role", "ORDERS")
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(generator.generateKeyPair().getPrivate())
                .compact();

        MockHttpServletResponse response = new MockHttpServletResponse();

        Authentication authentication = run(
                new JwtAuthorizationFilter(new JwtService(properties()), entryPoint),
                foreign, response);

        assertNull(authentication);
        assertEquals(401, response.getStatus());
    }

    @Test
    void clientModeStillPrefersTokenRolesOverTheLocalRecord() throws Exception {

        JwtAuthorizationFilter filter = new JwtAuthorizationFilter(
                new JwtService(properties()),
                username -> User.withUsername(username)
                        .password("")
                        .authorities(List.of())
                        .build(),
                entryPoint);

        Authentication authentication = run(filter,
                token("taiwo", "ADMIN"), new MockHttpServletResponse());

        assertTrue(authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN")));
    }

    @Test
    void clientModeFallsBackToTheLocalRecordWhenTheTokenHasNoRole() throws Exception {

        JwtAuthorizationFilter filter = new JwtAuthorizationFilter(
                new JwtService(properties()),
                username -> User.withUsername(username)
                        .password("")
                        .roles("LEGACY")
                        .build(),
                entryPoint);

        Authentication authentication = run(filter,
                token("taiwo", null), new MockHttpServletResponse());

        assertTrue(authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_LEGACY")));
    }
}
