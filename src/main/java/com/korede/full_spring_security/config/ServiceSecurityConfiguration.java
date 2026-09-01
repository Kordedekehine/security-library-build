package com.korede.full_spring_security.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Slf4j
@Configuration
@EnableConfigurationProperties(FullSecurityProperties.class)
public class ServiceSecurityConfiguration {

    @Bean
    SecurityFilterChain serviceSecurityFilterChain(
            HttpSecurity http,
            FullSecurityProperties properties) throws Exception {

        log.info("PUBLIC ENDPOINTS: {}", properties.getPublicEndpoints());

        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> {

                    properties.getPublicEndpoints()
                            .forEach(endpoint ->
                                    auth.requestMatchers(endpoint)
                                            .permitAll()
                            );

                    auth.anyRequest().authenticated();
                });

        return http.build();
    }
}
