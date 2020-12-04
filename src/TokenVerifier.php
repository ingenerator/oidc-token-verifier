<?php


namespace Ingenerator\OIDCTokenVerifier;


interface TokenVerifier
{

    /**
     * Verifies an OIDC token, checking:
     *
     * - That it is properly signed by the issuer (uses the CertificateProvider to fetch and cache
     *   public certificates)
     * - That it is not being used before the `issued at` time
     * - That it is not being used after the `expires` time
     * - That the issuer matches the expected issuer
     * - That the token matches a set of customisable extra constraints
     *
     * It is *strongly* recommended that you use the `extra_constraints` to validate the provided
     * audience, to ensure that a user cannot present a valid token issued for a different service.
     * This may not be necessary if you control the email address the token is issued for (e.g. a
     * service account) and verify that instead.
     *
     * @param string           $token
     * @param TokenConstraints $extra_constraints
     *
     * @return \Ingenerator\OIDCTokenVerifier\TokenVerificationResult
     */
    public function verify(string $token, TokenConstraints $extra_constraints): TokenVerificationResult;

}
