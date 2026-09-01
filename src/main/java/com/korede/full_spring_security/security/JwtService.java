package com.korede.full_spring_security.security;

import com.korede.full_spring_security.config.FullSecurityProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.function.Function;

@RequiredArgsConstructor
public class JwtService {

    private final FullSecurityProperties properties;

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public String extractRole(String token) {
        return extractClaim(token,
                claims -> claims.get("role", String.class)
        );
    }

    public boolean isSignatureValid(String token) {
        try {
            Jwts.parser()
                    .setSigningKey(getPublicKey())
                    .build()
                    .parseClaimsJws(token);

            return true;

        } catch (Exception e) {
            return false;
        }
    }

    public boolean isTokenValid(String token, String username) {

        try {

            if (!isSignatureValid(token)) {
                return false;
            }

            String usernameFromToken = extractUsername(token);

            Date expiration = extractClaim(token, Claims::getExpiration);

            if (expiration.before(new Date())) {
                return false;
            }

            return username.equals(usernameFromToken);

        } catch (Exception e) {
            return false;
        }
    }

    public <T> T extractClaim(String token,
            Function<Claims, T> claimsResolver) {

        Claims claims = Jwts.parser()
                .setSigningKey(getPublicKey())
                .setAllowedClockSkewSeconds(600)
                .build()
                .parseClaimsJws(token)
                .getBody();

        return claimsResolver.apply(claims);
    }

    private PublicKey getPublicKey() {

        try {

            String publicKey = properties.getClient().getPublicKey();

            byte[] keyBytes = Base64.getDecoder().decode(publicKey);

            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            return keyFactory.generatePublic(spec);

        } catch (Exception e) {
            throw new IllegalStateException("Unable to load JWT public key", e
            );
        }
    }

}
