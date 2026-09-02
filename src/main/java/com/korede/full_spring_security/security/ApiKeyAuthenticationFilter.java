package com.korede.full_spring_security.security;

import com.korede.full_spring_security.config.FullSecurityProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Authenticates a calling service by a shared key in a header.
 *
 * Keys are compared with a constant-time check, so a caller cannot learn a
 * valid key byte by byte from response timing. A request with no key header
 * is passed down the chain untouched, so public endpoints stay reachable and
 * the authorization rules decide.
 */
@Slf4j
public class ApiKeyAuthenticationFilter extends OncePerRequestFilter {

    private static final String ROLE_PREFIX = "ROLE_";

    private final String header;

    private final List<Credential> credentials;

    private final AuthenticationEntryPoint authenticationEntryPoint;

    public ApiKeyAuthenticationFilter(FullSecurityProperties.Service service,
            AuthenticationEntryPoint authenticationEntryPoint) {

        this.header = service.getHeader();
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.credentials = service.getCallers().stream()
                .map(Credential::new)
                .toList();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String presented = request.getHeader(header);

        if (presented == null || presented.isBlank()) {
            filterChain.doFilter(request, response);
            return;
        }

        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            filterChain.doFilter(request, response);
            return;
        }

        byte[] presentedBytes = presented.getBytes(StandardCharsets.UTF_8);

        Credential matched = null;

        // Check every credential rather than breaking early, so the work done
        // does not depend on which key was presented.
        for (Credential credential : credentials) {

            if (credential.matches(presentedBytes)) {
                matched = credential;
            }
        }

        if (matched == null) {

            log.debug("Rejected {} header: no matching caller", header);

            SecurityContextHolder.clearContext();

            authenticationEntryPoint.commence(request, response,
                    new BadCredentialsException("Unknown service key"));
            return;
        }

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(
                        matched.id, null, matched.authorities);

        authentication.setDetails(
                new WebAuthenticationDetailsSource().buildDetails(request));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        filterChain.doFilter(request, response);
    }

    /** A configured caller, with its key held as bytes for constant-time compare. */
    private static final class Credential {

        private final String id;

        private final byte[] key;

        private final List<GrantedAuthority> authorities;

        private Credential(FullSecurityProperties.Caller caller) {

            if (caller.getId() == null || caller.getId().isBlank()) {
                throw new IllegalStateException(
                        "full-security.service.callers entry is missing an id.");
            }

            if (caller.getKey() == null || caller.getKey().isBlank()) {
                throw new IllegalStateException(
                        "full-security.service.callers entry '" + caller.getId()
                        + "' is missing a key. Supply it from the environment, "
                        + "for example key=${ORDERS_SERVICE_KEY}.");
            }

            this.id = caller.getId();
            this.key = caller.getKey().getBytes(StandardCharsets.UTF_8);

            List<GrantedAuthority> granted = new ArrayList<>();

            caller.getRoles().stream()
                    .map(String::trim)
                    .filter(role -> !role.isEmpty())
                    .map(role -> role.startsWith(ROLE_PREFIX) ? role : ROLE_PREFIX + role)
                    .distinct()
                    .forEach(role -> granted.add(new SimpleGrantedAuthority(role)));

            this.authorities = List.copyOf(granted);
        }

        private boolean matches(byte[] presented) {
            return MessageDigest.isEqual(this.key, presented);
        }
    }
}
