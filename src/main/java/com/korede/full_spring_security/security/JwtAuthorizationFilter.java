package com.korede.full_spring_security.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * JWT
 *  ↓
 * Is it valid?
 *  ↓
 * Who is the user?
 *  ↓
 * Create Authentication
 *  ↓
 * SecurityContext
 */

@Slf4j
@RequiredArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
//    private final UserDetailsService userDetailsService;
private final UserAuthenticationProvider userAuthenticationProvider;


    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        // No token -> let Spring Security decide whether
        // the endpoint requires authentication.
        if (authHeader == null || authHeader.isBlank()) {
            filterChain.doFilter(request, response);
            return;
        }

        if (!authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        try {

            String jwt = authHeader.substring(7);

            String username = jwtService.extractUsername(jwt);

            if (username == null || SecurityContextHolder.getContext().getAuthentication() != null) {

                filterChain.doFilter(request, response);
                return;
            }

            boolean valid = jwtService.isTokenValid(jwt, username);

            if (!valid) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }

            UserDetails principal = userAuthenticationProvider.loadUser(username);

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                            principal,
                            null,
                            principal.getAuthorities()
                    );

            authentication.setDetails(new WebAuthenticationDetailsSource()
                    .buildDetails(request)
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);

            filterChain.doFilter(request, response);

        } catch (Exception e) {

            log.error("JWT authentication failed", e);

            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED
            );
        }

    }
}
