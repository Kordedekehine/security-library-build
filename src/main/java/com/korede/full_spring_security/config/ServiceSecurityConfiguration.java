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

        // SERVICE installs no authentication mechanism, so nothing can ever
        // satisfy a rule that requires a role or a logged-in caller.
        boolean requiresIdentity = properties.getRules().stream()
                .anyMatch(rule -> rule.isAuthenticated() || !rule.getRoles().isEmpty())
                || !properties.getActuator().getRoles().isEmpty();

        if (requiresIdentity) {
            log.warn("@FullSpringSecurity(type = SERVICE) has no authentication "
                    + "mechanism, so rules requiring a role or an authenticated "
                    + "caller can never be satisfied and will always return 403. "
                    + "Use type = CLIENT for JWT-authenticated services, or keep "
                    + "SERVICE rules to permit-all.");
        }

        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth ->
                        AuthorizationRules.apply(auth, properties));

        return http.build();
    }
}
