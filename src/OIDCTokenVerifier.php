<?php


namespace Ingenerator\OIDCTokenVerifier;


use Exception;
use Firebase\JWT\JWT;
use InvalidArgumentException;
use stdClass;
use UnexpectedValueException;
use function implode;
use function in_array;
use function is_string;
use function preg_match;

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

    public function verify(string $token, array $extra_constraints = []): TokenVerificationResult
    {
        try {
            $payload = $this->fetchCertificatesAndPerformBasicValidation($token);
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

        $failures = $this->validateExtraConstraints($payload, $extra_constraints);
        if ( ! empty($failures)) {
            return TokenVerificationResult::createFailure(
                new UnexpectedValueException(
                    'Token did not match constraints: '.implode(', ', $failures)
                )
            );
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
        $payload = JWT::decode($token, $certs, ['RS256']);

        if ($payload->iss !== $this->expected_issuer) {
            throw new UnexpectedValueException(
                'Mismatched token issuer: did not expect '.$payload->iss
            );
        }

        return $payload;
    }

    protected function validateExtraConstraints(object $payload, array $extra_constraints): array
    {
        $handlers = static::getConstraintMatchers();
        $failures = [];
        foreach ($extra_constraints as $constraint_name => $args) {
            if ( ! isset($handlers[$constraint_name])) {
                throw new InvalidArgumentException('Unknown token constraint '.$constraint_name);
            }

            if ( ! $handlers[$constraint_name]($payload, $args)) {
                $failures[] = $constraint_name;
            }
        }

        return $failures;
    }

    protected static function getConstraintMatchers(): array
    {
        return [
            'audience_exact' => function (stdClass $payload, string $expect) {
                return $expect === $payload->aud;
            },
            'email_exact'    => function (stdClass $payload, $expect) {
                $expect = is_string($expect) ? [$expect] : $expect;

                return in_array($payload->email, $expect, TRUE);
            },
            'email_match'    => function (stdClass $payload, string $regex) {
                return (bool) preg_match($regex, $payload->email);
            }
        ];
    }

}
