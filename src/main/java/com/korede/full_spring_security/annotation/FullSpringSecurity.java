package com.korede.full_spring_security.annotation;

import com.korede.full_spring_security.config.SecurityType;
import org.springframework.context.annotation.Import;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;


@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Import(FullSpringSecurityImportSelector.class)
public @interface FullSpringSecurity {

    SecurityType type();

    //SecurityType type() default SecurityType.SERVICE;
}

