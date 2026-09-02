package com.korede.full_spring_security.annotation;

import com.korede.full_spring_security.config.ClientSecurityConfiguration;
import org.springframework.context.annotation.Import;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Builds a stateless JWT security chain for this application.
 *
 * <pre>
 * &#64;SpringBootApplication
 * &#64;FullSpringSecurity
 * public class OrdersApplication { }
 * </pre>
 *
 * Requires a {@link com.korede.full_spring_security.security.UserAuthenticationProvider}
 * bean to resolve a verified token subject into a local user. Everything else
 * is configured under {@code full-security.*}.
 */
@Documented
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Import(ClientSecurityConfiguration.class)
public @interface FullSpringSecurity {
}
