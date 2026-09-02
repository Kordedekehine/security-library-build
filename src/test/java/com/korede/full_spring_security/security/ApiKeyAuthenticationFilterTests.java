package com.korede.full_spring_security.security;

import com.korede.full_spring_security.config.FullSecurityProperties;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

class ApiKeyAuthenticationFilterTests {

    private final FullSecurityAuthenticationEntryPoint entryPoint =
            new FullSecurityAuthenticationEntryPoint();

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    private FullSecurityProperties.Service service() {

        FullSecurityProperties.Caller caller = new FullSecurityProperties.Caller();
        caller.setId("orders-service");
        caller.setKey("s3cret-orders-key");
        caller.setRoles(List.of("SERVICE", "ORDERS"));

        FullSecurityProperties.Service service = new FullSecurityProperties.Service();
        service.setCallers(List.of(caller));

        return service;
    }

    private ApiKeyAuthenticationFilter filter() {
        return new ApiKeyAuthenticationFilter(service(), entryPoint);
    }

    @Test
    void authenticatesAKnownCallerAndGrantsItsRoles() throws Exception {

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-API-Key", "s3cret-orders-key");

        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter().doFilter(request, response, chain);

        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();

        assertNotNull(authentication);
        assertEquals("orders-service", authentication.getName());
        assertTrue(authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_SERVICE")));
        assertTrue(authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ORDERS")));

        verify(chain, times(1)).doFilter(request, response);
    }

    @Test
    void rejectsAnUnknownKeyWith401AndDoesNotContinueTheChain() throws Exception {

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-API-Key", "wrong-key");

        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter().doFilter(request, response, chain);

        assertEquals(401, response.getStatus());
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(chain, never()).doFilter(request, response);
    }

    @Test
    void passesThroughWhenNoKeyHeaderIsPresent() throws Exception {

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter().doFilter(request, response, chain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(chain, times(1)).doFilter(request, response);
    }

    @Test
    void refusesToStartWithACallerThatHasNoKey() {

        FullSecurityProperties.Caller caller = new FullSecurityProperties.Caller();
        caller.setId("orders-service");

        FullSecurityProperties.Service service = new FullSecurityProperties.Service();
        service.setCallers(List.of(caller));

        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> new ApiKeyAuthenticationFilter(service, entryPoint));

        assertTrue(e.getMessage().contains("orders-service"));
        assertTrue(e.getMessage().contains("missing a key"));
    }
}
