<?php


namespace Ingenerator\OIDCTokenVerifier;


class TokenVerificationFailedException extends \RuntimeException
{
    /**
     * @var \Ingenerator\OIDCTokenVerifier\TokenVerificationResult
     */
    private $result;

    public function __construct(TokenVerificationResult $result)
    {
        $this->result      = $result;
        $failure_exception = $result->getFailure();
        parent::__construct(
            'Token verification failed: '.$failure_exception->getMessage(),
            0,
            $failure_exception
        );
    }

    public function getVerificationResult(): \Ingenerator\OIDCTokenVerifier\TokenVerificationResult
    {
        return $this->result;
    }

}
