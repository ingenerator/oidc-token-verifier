<?php

declare(strict_types=1);

namespace Ingenerator\OIDCTokenVerifier;

use Exception;
use Firebase\JWT\JWT;
use stdClass;
use UnexpectedValueException;

class OIDCTokenVerifier implements TokenVerifier
{
    public function __construct(
        protected CertificateProvider $cert_provider,
        protected string $expected_issuer,
    ) {
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

    protected function fetchCertificatesAndPerformBasicValidation(string $token): stdClass
    {
        $certs = $this->cert_provider->getCertificates($this->expected_issuer);
        $payload = JWT::decode($token, $certs);

        if (!is_string($payload->iss ?? null)) {
            throw new UnexpectedValueException(
                sprintf(
                    'Token issuer is not a string (got %s',
                    json_encode($payload->iss ?? null, JSON_THROW_ON_ERROR)
                )
            );
        }

        if ($payload->iss !== $this->expected_issuer) {
            throw new UnexpectedValueException(
                'Mismatched token issuer: did not expect '.$payload->iss
            );
        }

        return $payload;
    }
}
