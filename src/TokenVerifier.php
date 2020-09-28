<?php


namespace Ingenerator\OIDCTokenVerifier;


interface TokenVerifier
{

    public function verify(string $token): TokenVerificationResult;

}
