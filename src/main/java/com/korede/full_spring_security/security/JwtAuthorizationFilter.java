package com.korede.full_spring_security.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT
 *  ↓
 * Is it valid?        (one parse: signature, expiry, issuer, audience)
 *  ↓
 * Who is the user?    (UserAuthenticationProvider resolves identity)
 *  ↓
 * What may they do?   (authorities from the token's role claim)
 *  ↓
 * SecurityContext
 */

@Slf4j
@RequiredArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private static final String ROLE_PREFIX = "ROLE_";

    private final JwtService jwtService;

    private final UserAuthenticationProvider userAuthenticationProvider;

    private final AuthenticationEntryPoint authenticationEntryPoint;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        // No bearer token -> let Spring Security decide whether
        // the endpoint requires authentication.
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Already authenticated earlier in the chain.
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            filterChain.doFilter(request, response);
            return;
        }

        try {

            String jwt = authHeader.substring(7);

            // Single parse - signature, expiry, issuer and audience.
            TokenClaims claims = jwtService.verify(jwt);

            String username = claims.subject();

            if (username == null || username.isBlank()) {
                throw new BadCredentialsException("Token carries no subject");
            }

            UserDetails principal = userAuthenticationProvider.loadUser(username);

            if (principal == null) {
                throw new BadCredentialsException("No user for token subject");
            }

            if (!principal.isEnabled()) {
                throw new DisabledException("Account is disabled");
            }

            if (!principal.isAccountNonLocked()) {
                throw new LockedException("Account is locked");
            }

            if (!principal.isAccountNonExpired() || !principal.isCredentialsNonExpired()) {
                throw new BadCredentialsException("Account or credentials expired");
            }

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                            principal,
                            null,
                            authorities(claims, principal)
                    );

            authentication.setDetails(new WebAuthenticationDetailsSource()
                    .buildDetails(request)
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);

        } catch (Exception e) {

            log.debug("JWT authentication failed: {}", e.getMessage());

            SecurityContextHolder.clearContext();

            authenticationEntryPoint.commence(request, response,
                    e instanceof org.springframework.security.core.AuthenticationException ae
                            ? ae
                            : new BadCredentialsException("Invalid token", e));
            return;
        }

        filterChain.doFilter(request, response);
    }

    /**
     * The issuer is the source of truth for what the caller may do, so
     * authorities come from the token's role claim. When the token carries no
     * roles the principal's own authorities are used, which keeps tokens that
     * predate the claim working.
     */
    private List<GrantedAuthority> authorities(TokenClaims claims, UserDetails principal) {

        List<String> roles = jwtService.extractRoles(claims);

        if (roles.isEmpty()) {
            return List.copyOf(principal.getAuthorities());
        }

        return roles.stream()
                .map(role -> role.startsWith(ROLE_PREFIX) ? role : ROLE_PREFIX + role)
                .distinct()
                .<GrantedAuthority>map(SimpleGrantedAuthority::new)
                .toList();
    }
}
