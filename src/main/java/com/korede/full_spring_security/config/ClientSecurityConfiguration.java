package com.korede.full_spring_security.config;

import com.korede.full_spring_security.security.JwtAuthorizationFilter;
import com.korede.full_spring_security.security.JwtService;
import com.korede.full_spring_security.security.UserAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
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
@RequiredArgsConstructor
@ConditionalOnBean(UserAuthenticationProvider.class)
@EnableConfigurationProperties(FullSecurityProperties.class)
public class ClientSecurityConfiguration {

   // private final FullSecurityProperties properties;
   //private final JwtService jwtService;

    private final UserAuthenticationProvider userAuthenticationProvider;

    @Bean
    public JwtService jwtService(FullSecurityProperties properties) {

        return new JwtService(properties);
    }

    @Bean
    SecurityFilterChain serviceSecurityFilterChain(
            HttpSecurity http, JwtService jwtService,
            FullSecurityProperties properties) throws Exception {

        log.info("PUBLIC ENDPOINTS: {}", properties.getPublicEndpoints());

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
