package com.korede.full_spring_security.config;

import jakarta.servlet.DispatcherType;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;

import java.util.List;

/**
 * Applies full-security.* authorization in a fixed order, shared by both
 * chains so CLIENT and SERVICE cannot drift apart:
 *
 *   0. ERROR/FORWARD/ASYNC     permitAll (container dispatches)
 *   1. public-endpoints        permitAll
 *   2. swagger paths           permitAll  (when enabled)
 *   3. actuator public ids     permitAll
 *   4. remaining /actuator/**  actuator roles
 *   5. rules, in order         permitAll / roles / authenticated
 *   6. anyRequest              authenticated
 *
 * Spring Security matches first-registered-first, so anything listed earlier
 * wins. Order the rules list from most specific to least.
 */
final class AuthorizationRules {

    private static final String ROLE_PREFIX = "ROLE_";

    private AuthorizationRules() {
    }

    static void apply(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry auth,
            FullSecurityProperties properties) {

        apply(auth, properties, List.of());
    }

    /**
     * @param fallbackRoles roles required by anything no rule matched. Empty
     *                      means any authenticated caller is accepted.
     */
    static void apply(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry auth,
            FullSecurityProperties properties, List<String> fallbackRoles) {

        // Validate the whole config before registering anything, so a bad
        // rule fails the context instead of half-building a filter chain.
        properties.getRules().forEach(AuthorizationRules::validate);

        // Container-initiated dispatches, not client requests. Without this a
        // 404 or 500 is forwarded to /error, which matches no rule and falls
        // through to anyRequest().authenticated() - so every error in the app
        // comes back as 401 and the real status is lost.
        auth.dispatcherTypeMatchers(
                        DispatcherType.ERROR,
                        DispatcherType.FORWARD,
                        DispatcherType.ASYNC)
                .permitAll();

        properties.getPublicEndpoints()
                .forEach(endpoint -> auth.requestMatchers(endpoint).permitAll());

        if (properties.getSwagger().isEnabled()) {
            properties.getSwagger().getPaths()
                    .forEach(path -> auth.requestMatchers(path).permitAll());
        }

        FullSecurityProperties.Actuator actuator = properties.getActuator();

        actuator.getPublicEndpoints().forEach(id -> auth
                .requestMatchers("/actuator/" + id, "/actuator/" + id + "/**")
                .permitAll());

        if (!actuator.getRoles().isEmpty()) {
            auth.requestMatchers("/actuator/**")
                    .hasAnyRole(stripPrefix(actuator.getRoles()));
        }

        properties.getRules().forEach(rule -> applyRule(auth, rule));

        if (fallbackRoles.isEmpty()) {
            auth.anyRequest().authenticated();
        } else {
            auth.anyRequest().hasAnyRole(stripPrefix(fallbackRoles));
        }
    }

    private static void applyRule(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry auth,
            FullSecurityProperties.Rule rule) {

        if (rule.getMethods().isEmpty()) {

            var url = auth.requestMatchers(rule.getPattern());

            if (rule.isPermitAll()) {
                url.permitAll();
            } else if (rule.isAuthenticated()) {
                url.authenticated();
            } else {
                url.hasAnyRole(stripPrefix(rule.getRoles()));
            }

            return;
        }

        // requestMatchers takes a single method, so each one is its own rule.
        for (String method : rule.getMethods()) {

            var url = auth.requestMatchers(
                    HttpMethod.valueOf(method.trim().toUpperCase()),
                    rule.getPattern());

            if (rule.isPermitAll()) {
                url.permitAll();
            } else if (rule.isAuthenticated()) {
                url.authenticated();
            } else {
                url.hasAnyRole(stripPrefix(rule.getRoles()));
            }
        }
    }

    private static void validate(FullSecurityProperties.Rule rule) {

        if (rule.getPattern() == null || rule.getPattern().isBlank()) {
            throw new IllegalStateException(
                    "full-security.rules entry is missing a pattern.");
        }

        int outcomes = (rule.isPermitAll() ? 1 : 0)
                + (rule.isAuthenticated() ? 1 : 0)
                + (rule.getRoles().isEmpty() ? 0 : 1);

        if (outcomes != 1) {
            throw new IllegalStateException(
                    "full-security.rules entry for '" + rule.getPattern()
                    + "' must choose exactly one of: roles, permit-all, "
                    + "authenticated. Found " + outcomes + ".");
        }
    }

    /**
     * hasAnyRole re-adds the ROLE_ prefix, so a configured "ROLE_ADMIN" would
     * become ROLE_ROLE_ADMIN. Accept either spelling.
     */
    private static String[] stripPrefix(List<String> roles) {

        return roles.stream()
                .map(String::trim)
                .filter(role -> !role.isEmpty())
                .map(role -> role.startsWith(ROLE_PREFIX)
                        ? role.substring(ROLE_PREFIX.length())
                        : role)
                .toArray(String[]::new);
    }
}
