package com.korede.full_spring_security.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
 * Still honoured?     (TokenRevocationChecker, when any are registered)
 *  ↓
 * Who is the user?    (UserAuthenticationProvider resolves the subject)
 *  ↓
 * What may they do?   (authorities from the token's role claim)
 *  ↓
 * SecurityContext
 */
@Slf4j
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private static final String ROLE_PREFIX = "ROLE_";

    private final JwtService jwtService;

    private final UserAuthenticationProvider userAuthenticationProvider;

    private final AuthenticationEntryPoint authenticationEntryPoint;

    private final List<TokenRevocationChecker> revocationCheckers;

    public JwtAuthorizationFilter(JwtService jwtService,
            UserAuthenticationProvider userAuthenticationProvider,
            AuthenticationEntryPoint authenticationEntryPoint) {

        this(jwtService, userAuthenticationProvider, authenticationEntryPoint, List.of());
    }

    public JwtAuthorizationFilter(JwtService jwtService,
            UserAuthenticationProvider userAuthenticationProvider,
            AuthenticationEntryPoint authenticationEntryPoint,
            List<TokenRevocationChecker> revocationCheckers) {

        this.jwtService = jwtService;
        this.userAuthenticationProvider = userAuthenticationProvider;
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.revocationCheckers = List.copyOf(revocationCheckers);
    }

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

            String subject = claims.subject();

            if (subject == null || subject.isBlank()) {
                throw new BadCredentialsException("Token carries no subject");
            }

            if (isRevoked(claims)) {
                throw new BadCredentialsException("Token has been revoked");
            }

            UserDetails user = userAuthenticationProvider.loadUser(subject);

            if (user == null) {
                throw new BadCredentialsException("No user for token subject");
            }

            if (!user.isEnabled()) {
                throw new DisabledException("Account is disabled");
            }

            if (!user.isAccountNonLocked()) {
                throw new LockedException("Account is locked");
            }

            if (!user.isAccountNonExpired() || !user.isCredentialsNonExpired()) {
                throw new BadCredentialsException("Account or credentials expired");
            }

            List<GrantedAuthority> authorities = tokenAuthorities(claims);

            // The issuer is authoritative for roles; the local record is only
            // consulted when the token says nothing about them.
            if (authorities.isEmpty()) {
                authorities = List.copyOf(user.getAuthorities());
            }

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                            user, null, authorities);

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
     * A checker that throws is treated as a rejection: an unreachable denylist
     * must not become a way to use revoked tokens.
     */
    private boolean isRevoked(TokenClaims claims) {

        for (TokenRevocationChecker checker : revocationCheckers) {

            try {
                if (checker.isRevoked(claims)) {
                    return true;
                }

            } catch (Exception e) {
                log.warn("Revocation check {} failed; rejecting the token",
                        checker.getClass().getName(), e);
                return true;
            }
        }

        return false;
    }

    /** Authorities named by the token's role claim, ROLE_-prefixed. */
    private List<GrantedAuthority> tokenAuthorities(TokenClaims claims) {

        return jwtService.extractRoles(claims).stream()
                .map(role -> role.startsWith(ROLE_PREFIX) ? role : ROLE_PREFIX + role)
                .distinct()
                .<GrantedAuthority>map(SimpleGrantedAuthority::new)
                .toList();
    }
}
