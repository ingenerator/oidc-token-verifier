<?php

namespace Ingenerator\OIDCTokenVerifier;

use RuntimeException;

class TokenVerificationFailedException extends RuntimeException
{
    public function __construct(
        private readonly TokenVerificationResult $result)
    {
        $failure_exception = $this->result->getFailure();
        parent::__construct(
            'Token verification failed: '.$failure_exception->getMessage(),
            0,
            $failure_exception
        );
    }

    public function getVerificationResult(): TokenVerificationResult
    {
        return $this->result;
    }
}
