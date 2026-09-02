package com.korede.full_spring_security.config;

import com.korede.full_spring_security.security.ApiKeyAuthenticationFilter;
import com.korede.full_spring_security.security.FullSecurityAccessDeniedHandler;
import com.korede.full_spring_security.security.FullSecurityAuthenticationEntryPoint;
import com.korede.full_spring_security.security.JwtAuthorizationFilter;
import com.korede.full_spring_security.security.JwtService;
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
 * Security for a service called by other services.
 *
 * Callers arrive holding a JWT they obtained elsewhere - your auth service
 * exchanges their credentials for one. This service does not issue tokens; it
 * verifies the one presented and checks it carries the role that opens this
 * service.
 *
 * CSRF disabled
 *         ↓
 * STATELESS
 *         ↓
 * public endpoints
 *         ↓
 * JWT verification
 *         ↓
 * required role
 *         ↓
 * 401 / 403 as JSON
 *
 * The difference from CLIENT is only who the caller is: there is no local
 * user record for another service, so the token's subject is the principal
 * and no UserAuthenticationProvider is needed.
 */

@Slf4j
@EnableMethodSecurity
@EnableConfigurationProperties(FullSecurityProperties.class)
public class ServiceSecurityConfiguration {

    @Bean
    public JwtService jwtService(FullSecurityProperties properties) {

        return new JwtService(properties);
    }

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
            JwtService jwtService,
            FullSecurityProperties properties,
            AuthenticationEntryPoint authenticationEntryPoint,
            AccessDeniedHandler accessDeniedHandler) throws Exception {

        FullSecurityProperties.Service service = properties.getService();

        log.info("PUBLIC ENDPOINTS: {}", properties.getPublicEndpoints());
        log.info("REQUIRED ROLES: {}", service.getRequiredRoles().isEmpty()
                ? "any verified token" : service.getRequiredRoles());

        http
                .csrf(csrf -> csrf.disable())

                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                .authorizeHttpRequests(auth ->
                        AuthorizationRules.apply(auth, properties,
                                service.getRequiredRoles()))

                .exceptionHandling(handling -> handling
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler)
                )

                .addFilterBefore(
                        new JwtAuthorizationFilter(jwtService, authenticationEntryPoint),
                        UsernamePasswordAuthenticationFilter.class);

        // Optional second mechanism, for callers that cannot obtain a token.
        if (!service.getCallers().isEmpty()) {

            log.info("API KEY CALLERS: {}", service.getCallers().stream()
                    .map(FullSecurityProperties.Caller::getId).toList());

            http.addFilterBefore(
                    new ApiKeyAuthenticationFilter(service, authenticationEntryPoint),
                    JwtAuthorizationFilter.class);
        }

        return http.build();
    }
}
