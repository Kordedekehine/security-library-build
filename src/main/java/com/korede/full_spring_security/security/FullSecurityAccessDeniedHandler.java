package com.korede.full_spring_security.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;

/** Authenticated but not permitted -> 403 with the same payload shape. */
public class FullSecurityAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
            AccessDeniedException accessDeniedException) throws IOException {

        FullSecurityErrorWriter.write(request, response,
                HttpServletResponse.SC_FORBIDDEN,
                "Forbidden",
                "Authenticated but not permitted to access this resource.");
    }
}
