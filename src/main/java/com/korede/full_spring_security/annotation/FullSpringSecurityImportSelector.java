package com.korede.full_spring_security.annotation;

import com.korede.full_spring_security.config.ClientSecurityConfiguration;
import com.korede.full_spring_security.config.SecurityType;
import com.korede.full_spring_security.config.ServiceSecurityConfiguration;
import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.type.AnnotationMetadata;

import java.util.Map;

public class FullSpringSecurityImportSelector implements ImportSelector {


    @Override
    public String[] selectImports(AnnotationMetadata metadata) {

        Map<String, Object> attributes =
                metadata.getAnnotationAttributes(
                        FullSpringSecurity.class.getName()
                );

        SecurityType type =
                (SecurityType) attributes.get("type");

        if (type == SecurityType.CLIENT) {
            return new String[]{
                    ClientSecurityConfiguration.class.getName()
            };
        }

        if (type == SecurityType.SERVICE) {
            return new String[]{
                    ServiceSecurityConfiguration.class.getName()
            };
        }

        throw new IllegalArgumentException("Unsupported security type: " + type);
    }
}

