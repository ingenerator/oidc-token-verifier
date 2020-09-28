<?php


namespace Ingenerator\OIDCTokenVerifier;


use Exception;
use Firebase\JWT\JWT;
use UnexpectedValueException;

class OIDCTokenVerifier implements TokenVerifier
{
    /**
     * @var \Ingenerator\OIDCTokenVerifier\CertificateProvider
     */
    protected $cert_provider;

    /**
     * @var string
     */
    protected $expected_issuer;

    public function __construct(CertificateProvider $cert_provider, string $expected_issuer)
    {
        $this->cert_provider   = $cert_provider;
        $this->expected_issuer = $expected_issuer;
    }

    public function verify(string $token): TokenVerificationResult
    {

        try {
            return TokenVerificationResult::createSuccess(
                $this->fetchCertificatesAndValidate($token)
            );
        } catch (CertificateDiscoveryFailedException $e) {
            // Bubble this up - it's unlikely to actually be an auth issue
            throw $e;
        } catch (Exception $e) {
            return TokenVerificationResult::createFailure($e);
        }
    }

    /**
     * @param string $token
     *
     * @return object
     */
    protected function fetchCertificatesAndValidate(string $token): object
    {
        $certs   = $this->cert_provider->getCertificates($this->expected_issuer);
        $payload = JWT::decode($token, $certs, ['RS256']);

        if ($payload->iss !== $this->expected_issuer) {
            throw new UnexpectedValueException(
                'Mismatched token issuer: did not expect '.$payload->iss
            );
        }

        return $payload;
    }

}
