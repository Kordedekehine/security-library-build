package com.korede.full_spring_security.annotation;

import com.korede.full_spring_security.config.ClientSecurityConfiguration;
import com.korede.full_spring_security.config.SecurityType;
import com.korede.full_spring_security.config.ServiceSecurityConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.core.type.AnnotationMetadata;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class FullSpringSecurityImportSelectorTests {

    private final FullSpringSecurityImportSelector selector =
            new FullSpringSecurityImportSelector();

    @FullSpringSecurity(type = SecurityType.CLIENT)
    private static class ClientApp {
    }

    @FullSpringSecurity(type = SecurityType.SERVICE)
    private static class ServiceApp {
    }

    @Test
    void clientTypeImportsOnlyTheClientChain() {

        assertArrayEquals(
                new String[]{ClientSecurityConfiguration.class.getName()},
                selector.selectImports(AnnotationMetadata.introspect(ClientApp.class))
        );
    }

    @Test
    void serviceTypeImportsOnlyTheServiceChain() {

        assertArrayEquals(
                new String[]{ServiceSecurityConfiguration.class.getName()},
                selector.selectImports(AnnotationMetadata.introspect(ServiceApp.class))
        );
    }
}
