package com.korede.full_spring_security.config;

import com.korede.full_spring_security.security.ApiKeyAuthenticationFilter;
import com.korede.full_spring_security.security.FullSecurityAccessDeniedHandler;
import com.korede.full_spring_security.security.FullSecurityAuthenticationEntryPoint;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Service-to-service security: callers identify themselves with a shared key
 * in a header rather than a user token.
 *
 * CSRF disabled
 *         ↓
 * STATELESS
 *         ↓
 * public endpoints
 *         ↓
 * API key authentication
 *         ↓
 * role rules
 *         ↓
 * 401 / 403 as JSON
 */

@Slf4j
@EnableMethodSecurity
@EnableConfigurationProperties(FullSecurityProperties.class)
public class ServiceSecurityConfiguration {

    @Bean
    public AuthenticationEntryPoint fullSecurityAuthenticationEntryPoint() {

        return new FullSecurityAuthenticationEntryPoint();
    }

    @Bean
    public AccessDeniedHandler fullSecurityAccessDeniedHandler() {

        return new FullSecurityAccessDeniedHandler();
    }

    @Bean
    SecurityFilterChain serviceSecurityFilterChain(
            HttpSecurity http,
            FullSecurityProperties properties,
            AuthenticationEntryPoint authenticationEntryPoint,
            AccessDeniedHandler accessDeniedHandler) throws Exception {

        log.info("PUBLIC ENDPOINTS: {}", properties.getPublicEndpoints());

        boolean hasCallers = !properties.getService().getCallers().isEmpty();

        boolean requiresIdentity = properties.getRules().stream()
                .anyMatch(rule -> rule.isAuthenticated() || !rule.getRoles().isEmpty())
                || !properties.getActuator().getRoles().isEmpty();

        if (requiresIdentity && !hasCallers) {
            log.warn("@FullSpringSecurity(type = SERVICE) has rules requiring a "
                    + "role or an authenticated caller, but no "
                    + "full-security.service.callers are configured - nothing "
                    + "can satisfy them and those endpoints will always return "
                    + "403.");
        }

        if (hasCallers) {
            log.info("SERVICE CALLERS: {}", properties.getService().getCallers()
                    .stream().map(FullSecurityProperties.Caller::getId).toList());
        }

        http
                .csrf(csrf -> csrf.disable())

                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                .authorizeHttpRequests(auth ->
                        AuthorizationRules.apply(auth, properties))

                .exceptionHandling(handling -> handling
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler)
                );

        if (hasCallers) {
            http.addFilterBefore(
                    new ApiKeyAuthenticationFilter(
                            properties.getService(), authenticationEntryPoint),
                    UsernamePasswordAuthenticationFilter.class);
        }

        return http.build();
    }
}
