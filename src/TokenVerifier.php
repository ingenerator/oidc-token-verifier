<?php


namespace Ingenerator\OIDCTokenVerifier;


interface TokenVerifier
{

    public function verify(string $token): TokenVerificationResult;

    /**
     * @param string $token
     *
     *
     * @return \Ingenerator\OIDCTokenVerifier\TokenVerificationResult
     * @throws InvalidTokenException
     */
    public function mustVerify(string $token): TokenVerificationResult;

}
