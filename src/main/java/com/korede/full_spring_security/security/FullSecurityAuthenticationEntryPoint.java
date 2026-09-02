package com.korede.full_spring_security.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;

/**
 * Missing or unusable credentials -> 401. Without this, Spring answers an
 * unauthenticated request to a protected endpoint with 403, which tells the
 * caller "you may not" when the real answer is "you have not identified".
 */
public class FullSecurityAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) throws IOException {

        response.setHeader("WWW-Authenticate", "Bearer");

        FullSecurityErrorWriter.write(request, response,
                HttpServletResponse.SC_UNAUTHORIZED,
                "Unauthorized",
                "Authentication required. Supply a valid Bearer token.");
    }
}
