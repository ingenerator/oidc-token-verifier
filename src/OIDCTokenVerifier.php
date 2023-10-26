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

    public function verify(string $token, TokenConstraints $extra_constraints): TokenVerificationResult
    {
        try {
            $payload = $this->fetchCertificatesAndPerformBasicValidation($token);
            $extra_constraints->mustMatch($payload);
        } catch (CertificateDiscoveryFailedException $e) {
            // Bubble this up - it's unlikely to actually be an auth issue
            throw $e;
        } catch (Exception $e) {
            // This is an undesirably broad catch but the firebase/jwt throws quite a range of
            // exceptions based on the content of the token and certificate string values so an
            // improperly formatted token could give an InvalidArgumentException /
            // UnexpectedValueException etc all of which are really just invalid values rather than
            // code errors.
            return TokenVerificationResult::createFailure($e);
        }

        return TokenVerificationResult::createSuccess($payload);

    }

    /**
     * @param string $token
     *
     * @return object
     */
    protected function fetchCertificatesAndPerformBasicValidation(string $token): object
    {
        $certs   = $this->cert_provider->getCertificates($this->expected_issuer);
        $payload = JWT::decode($token, $certs);

        if ($payload->iss !== $this->expected_issuer) {
            throw new UnexpectedValueException(
                'Mismatched token issuer: did not expect '.$payload->iss
            );
        }

        return $payload;
    }

}
