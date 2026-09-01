package com.korede.full_spring_security.autoconfigure;

import com.korede.full_spring_security.config.FullSecurityProperties;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

/**
 * Binds full-security.* for any consumer that has the jar on its classpath,
 * whether or not it uses @FullSpringSecurity. The filter chains themselves
 * stay annotation-driven via FullSpringSecurityImportSelector.
 */
@AutoConfiguration
@EnableConfigurationProperties(FullSecurityProperties.class)
public class FullSecurityAutoConfiguration {

}
