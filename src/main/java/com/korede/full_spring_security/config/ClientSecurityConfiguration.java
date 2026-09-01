package com.korede.full_spring_security.config;

import com.korede.full_spring_security.security.JwtAuthorizationFilter;
import com.korede.full_spring_security.security.JwtService;
import com.korede.full_spring_security.security.UserAuthenticationProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * CSRF disabled
 *         ↓
 * STATELESS
 *         ↓
 * public endpoints
 *         ↓
 * JWT authentication
 *         ↓
 * authenticated endpoints
 */

@Slf4j
@EnableConfigurationProperties(FullSecurityProperties.class)
public class ClientSecurityConfiguration {

    @Bean
    public JwtService jwtService(FullSecurityProperties properties) {

        return new JwtService(properties);
    }

    @Bean
    SecurityFilterChain clientSecurityFilterChain(
            HttpSecurity http, JwtService jwtService,
            FullSecurityProperties properties,
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
                        jwtService, userAuthenticationProvider);

        http
                .csrf(csrf -> csrf.disable())

                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                .authorizeHttpRequests(auth -> {

                    properties.getPublicEndpoints()
                            .forEach(endpoint ->
                                    auth.requestMatchers(endpoint)
                                            .permitAll()
                            );

                    auth.anyRequest().authenticated();
                })

                .addFilterBefore(jwtAuthorizationFilter,
                        UsernamePasswordAuthenticationFilter.class
                );


        return http.build();
    }
}
