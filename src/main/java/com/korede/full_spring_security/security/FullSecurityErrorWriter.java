package com.korede.full_spring_security.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;

import java.io.IOException;

/**
 * Writes the library's error payload. Messages are fixed strings - nothing
 * from the token or the request body is echoed back to the caller.
 */
final class FullSecurityErrorWriter {

    private FullSecurityErrorWriter() {
    }

    static void write(HttpServletRequest request, HttpServletResponse response,
            int status, String error, String message) throws IOException {

        if (response.isCommitted()) {
            return;
        }

        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        response.getWriter().write(
                "{\"status\":" + status
                + ",\"error\":\"" + escape(error)
                + "\",\"message\":\"" + escape(message)
                + "\",\"path\":\"" + escape(request.getRequestURI())
                + "\"}");
    }

    private static String escape(String value) {

        if (value == null) {
            return "";
        }

        StringBuilder out = new StringBuilder(value.length());

        for (char c : value.toCharArray()) {

            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }

        return out.toString();
    }
}
