package com.korede.full_spring_security.config;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Covers the rule validation that runs before any matcher is registered.
 * Matching itself is exercised end to end against a running app.
 */
class AuthorizationRulesTests {

    private FullSecurityProperties.Rule rule(String pattern) {
        FullSecurityProperties.Rule rule = new FullSecurityProperties.Rule();
        rule.setPattern(pattern);
        return rule;
    }

    private IllegalStateException applyExpectingFailure(FullSecurityProperties.Rule rule) {
        FullSecurityProperties properties = new FullSecurityProperties();
        properties.getRules().add(rule);
        return assertThrows(IllegalStateException.class,
                () -> AuthorizationRules.apply(null, properties));
    }

    @Test
    void rejectsARuleWithNoOutcome() {

        IllegalStateException e = applyExpectingFailure(rule("/api/**"));

        assertTrue(e.getMessage().contains("exactly one of"));
        assertTrue(e.getMessage().contains("/api/**"));
    }

    @Test
    void rejectsARuleWithTwoOutcomes() {

        FullSecurityProperties.Rule rule = rule("/api/**");
        rule.setPermitAll(true);
        rule.setRoles(List.of("ADMIN"));

        assertTrue(applyExpectingFailure(rule).getMessage().contains("Found 2"));
    }

    @Test
    void rejectsARuleWithNoPattern() {

        FullSecurityProperties.Rule rule = new FullSecurityProperties.Rule();
        rule.setRoles(List.of("ADMIN"));

        assertTrue(applyExpectingFailure(rule).getMessage().contains("missing a pattern"));
    }

    @Test
    void defaultsLeaveEveryOptionalSurfaceClosed() {

        FullSecurityProperties properties = new FullSecurityProperties();

        assertTrue(properties.getPublicEndpoints().isEmpty());
        assertTrue(properties.getRules().isEmpty());
        assertTrue(properties.getActuator().getPublicEndpoints().isEmpty());
        assertTrue(properties.getActuator().getRoles().isEmpty());
        assertEquals(false, properties.getSwagger().isEnabled());
        assertEquals(false, properties.getCors().isEnabled());
    }

    @Test
    void swaggerPathsCoverTheUsualSpringdocSurfaces() {

        List<String> paths = new FullSecurityProperties().getSwagger().getPaths();

        assertTrue(paths.contains("/swagger-ui/**"));
        assertTrue(paths.contains("/v3/api-docs/**"));
    }
}
