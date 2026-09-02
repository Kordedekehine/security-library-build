package com.korede.full_spring_security.security;

/**
 * Rejects a token that verified correctly but should no longer be honoured.
 *
 * A JWT is valid until it expires - nothing in the token itself can withdraw
 * it. Without a check like this, a leaked token stays usable for the whole of
 * its lifetime and a logout cannot take effect. Implement this to consult
 * whatever records that: a denylist of {@code jti}, a per-user
 * "tokens issued before this instant are void" timestamp, a session store.
 *
 * <pre>
 * &#64;Bean
 * TokenRevocationChecker denylist(RevokedTokenRepository repository) {
 *     return claims -&gt; repository.existsByJti(claims.id());
 * }
 * </pre>
 *
 * Every registered checker is consulted and any one of them can reject the
 * token. Checks run on each request after signature verification and before
 * the user lookup, so keep them fast - cache rather than query per request.
 *
 * A checker that throws is treated as a rejection, so an unreachable denylist
 * fails closed rather than letting revoked tokens through.
 */
@FunctionalInterface
public interface TokenRevocationChecker {

    /**
     * @param claims the verified claims - signature, expiry, issuer and
     *               audience have already passed
     * @return true to reject the request with 401
     */
    boolean isRevoked(TokenClaims claims);
}
