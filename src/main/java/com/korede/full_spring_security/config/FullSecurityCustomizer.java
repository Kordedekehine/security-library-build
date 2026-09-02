package com.korede.full_spring_security.config;

import org.springframework.core.Ordered;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * Hook for anything this library does not expose as a property.
 *
 * Every {@code FullSecurityCustomizer} bean is applied to the chain after the
 * library has configured it and before it is built, so a customizer can add to
 * the chain or override what the library set - re-enable CSRF, add security
 * headers, register another filter, scope a matcher.
 *
 * <pre>
 * &#64;Bean
 * FullSecurityCustomizer strictHeaders() {
 *     return http -&gt; http.headers(headers -&gt; headers
 *             .httpStrictTransportSecurity(hsts -&gt; hsts.maxAgeInSeconds(31536000))
 *             .referrerPolicy(referrer -&gt; referrer.policy(SAME_ORIGIN)));
 * }
 * </pre>
 *
 * Customizers run in {@link Ordered} order, lowest first. Because they run
 * last, a customizer can undo the library's own choices - including disabling
 * authentication entirely. Review them the way you would review the chain.
 */
@FunctionalInterface
public interface FullSecurityCustomizer extends Ordered {

    /**
     * @param http the chain under construction, already configured by the
     *             library. Do not call {@code build()}.
     */
    void customize(HttpSecurity http) throws Exception;

    @Override
    default int getOrder() {
        return Ordered.LOWEST_PRECEDENCE;
    }
}
