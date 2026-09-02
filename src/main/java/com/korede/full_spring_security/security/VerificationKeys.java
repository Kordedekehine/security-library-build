package com.korede.full_spring_security.security;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;

/**
 * Turns a configured public key string into a {@link PublicKey}.
 *
 * The algorithm is not assumed. RSA, EC and EdDSA keys all arrive as X.509
 * SubjectPublicKeyInfo, and the algorithm is identified inside that structure,
 * so each supported KeyFactory is tried until one accepts the bytes.
 */
final class VerificationKeys {

    private static final List<String> ALGORITHMS = List.of("RSA", "EC", "EdDSA");

    private VerificationKeys() {
    }

    /**
     * @param encoded   Base64 of an X.509 public key. PEM armour, whitespace
     *                  and URL-safe alphabets are all tolerated.
     * @param algorithm optional hint ("RSA", "EC", "EdDSA"); null to detect
     */
    static PublicKey parse(String encoded, String algorithm) {

        byte[] der = decode(encoded);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(der);

        List<String> candidates = (algorithm == null || algorithm.isBlank())
                ? ALGORITHMS
                : List.of(algorithm.trim());

        for (String candidate : candidates) {

            try {
                return KeyFactory.getInstance(candidate).generatePublic(spec);

            } catch (Exception ignored) {
                // Wrong factory for this key - try the next.
            }
        }

        throw new IllegalStateException(
                "Could not read the configured public key as any of " + candidates
                + ". Expected Base64 of an X.509 public key - the output of:\n\n"
                + "  openssl rsa -in private.pem -pubout -outform DER | base64\n");
    }

    /** Accepts PEM armour and either Base64 alphabet, so pasted keys just work. */
    private static byte[] decode(String encoded) {

        String cleaned = encoded
                .replaceAll("-----BEGIN [A-Z ]+-----", "")
                .replaceAll("-----END [A-Z ]+-----", "")
                .replaceAll("\\s", "");

        try {
            return Base64.getDecoder().decode(cleaned);

        } catch (IllegalArgumentException e) {
            return Base64.getUrlDecoder().decode(cleaned);
        }
    }
}
