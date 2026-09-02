package com.korede.full_spring_security.config;

import com.korede.full_spring_security.security.FullSecurityAccessDeniedHandler;
import com.korede.full_spring_security.security.FullSecurityAuthenticationEntryPoint;
import com.korede.full_spring_security.security.JwtAuthorizationFilter;
import com.korede.full_spring_security.security.JwtService;
import com.korede.full_spring_security.security.UserAuthenticationProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * CSRF disabled
 *         ↓
 * CORS (when enabled)
 *         ↓
 * STATELESS
 *         ↓
 * public endpoints
 *         ↓
 * JWT authentication
 *         ↓
 * authenticated endpoints
 *         ↓
 * 401 / 403 as JSON
 */

@Slf4j
@EnableMethodSecurity
@EnableConfigurationProperties(FullSecurityProperties.class)
public class ClientSecurityConfiguration {

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
    SecurityFilterChain clientSecurityFilterChain(
            HttpSecurity http, JwtService jwtService,
            FullSecurityProperties properties,
            AuthenticationEntryPoint authenticationEntryPoint,
            AccessDeniedHandler accessDeniedHandler,
            ObjectProvider<UserAuthenticationProvider> providers) throws Exception {

        log.info("PUBLIC ENDPOINTS: {}", properties.getPublicEndpoints());

        UserAuthenticationProvider userAuthenticationProvider =
                providers.getIfAvailable();

        if (userAuthenticationProvider == null) {
            throw new IllegalStateException(
                    "@FullSpringSecurity(type = CLIENT) requires a "
                    + UserAuthenticationProvider.class.getName() + " bean. "
                    + "Expose one, for example:\n\n"
                    + "  @Service\n"
                    + "  public class LoadUser implements UserAuthenticationProvider {\n"
                    + "      public UserDetails loadUser(String username) { ... }\n"
                    + "  }\n");
        }

        JwtAuthorizationFilter jwtAuthorizationFilter = new JwtAuthorizationFilter(
                jwtService, userAuthenticationProvider, authenticationEntryPoint);

        http
                .csrf(csrf -> csrf.disable())

                .cors(cors -> {
                    if (properties.getCors().isEnabled()) {
                        cors.configurationSource(corsConfigurationSource(properties));
                    } else {
                        cors.disable();
                    }
                })

                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                .authorizeHttpRequests(auth ->
                        AuthorizationRules.apply(auth, properties))

                .exceptionHandling(handling -> handling
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler)
                )

                .addFilterBefore(jwtAuthorizationFilter,
                        UsernamePasswordAuthenticationFilter.class
                );

        return http.build();
    }

    private CorsConfigurationSource corsConfigurationSource(
            FullSecurityProperties properties) {

        FullSecurityProperties.Cors cors = properties.getCors();

        log.info("CORS ENABLED, ALLOWED ORIGINS: {}", cors.getAllowedOrigins());

        CorsConfiguration configuration = new CorsConfiguration();

        // setAllowedOriginPatterns supports wildcards, which plain
        // setAllowedOrigins rejects when credentials are allowed.
        configuration.setAllowedOriginPatterns(cors.getAllowedOrigins());
        configuration.setAllowedMethods(cors.getAllowedMethods());
        configuration.setAllowedHeaders(cors.getAllowedHeaders());
        configuration.setAllowCredentials(cors.isAllowCredentials());
        configuration.setMaxAge(cors.getMaxAgeSeconds());

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }
}
