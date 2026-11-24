<?php

namespace Ingenerator\OIDCTokenVerifier;

use InvalidArgumentException;
use stdClass;

use function array_diff;
use function array_intersect_key;
use function parse_url;

/**
 * Represents extra constraints that must also match for a token.
 *
 * By default the token verifier only checks the issuer and signature. So if, for example, you are configured
 * to accept tokens issued for a google service account, it will allow *any* service account token generated for
 * *any* purpose.
 *
 * You will almost always want to extend this validation to ensure that the token was issued to authorise an action
 * on your service - e.g. by validating the `audience` the token was issued for, and the `email` address it was
 * issued to. In some cases this will be handled in application code - e.g. by looking up a service account email
 * in an authentication database and performing custom usecase-based authorization logic.
 *
 * However in most simple cases it may be better to pre-define the audience/emails that are allowed to be used
 * and pass them through this class to make these checks as part of the initial token verification.
 */
class TokenConstraints
{
    /**
     * @var array<string, mixed>
     */
    protected array $constraints = [];

    /**
     * @var array<string, callable(stdClass, mixed):bool>
     */
    protected array $matchers;

    /**
     * An empty constraints object that will only check the signature is valid.
     *
     * *ONLY* use this in production code if you are separately validating the email address and/or audience of the
     * token in your own code (see class docs).
     */
    public static function signatureCheckOnly(): TokenConstraints
    {
        return new self([]);
    }

    /**
     * Supported constraints:
     *
     *  * `audience_exact`: the token `aud` must match the provided value
     *  * `audience_path_and_query`: the token `aud` is assumed to be a URL. The path and querystring portion must match expected value
     *  * `email_exact`: the token `email` must be present, and must match a known email / array of emails
     *  * `email_match`: the token `email` must be present, and must match the provided regex
     *
     * @param array{
     *     audience_exact?: string,
     *     audience_path_and_query?: string,
     *     email_exact?: string|list<string>,
     *     email_match?: string,
     *     ...<string, mixed>
     * } $constraints
     *
     * @throws InvalidArgumentException if a constraint type is not defined
     */
    public function __construct(array $constraints)
    {
        $matchers = array_intersect_key(static::getAllMatchers(), $constraints);
        if (count($matchers) < count($constraints)) {
            throw new InvalidArgumentException(
                sprintf(
                    'Unknown constraint types: %s',
                    implode(',', array_diff(array_keys($constraints), array_keys($matchers)))
                )
            );
        }

        $this->matchers = $matchers;
        $this->constraints = $constraints;
    }

    /**
     * @return array<string, callable(stdClass, mixed):bool>
     */
    protected static function getAllMatchers(): array
    {
        static $all_matchers;
        if (!$all_matchers) {
            $all_matchers = [
                'audience_exact' => fn (stdClass $payload, string $expect): bool => $expect === $payload->aud,
                'audience_path_and_query' => fn (stdClass $payload, string $expect): bool => self::parseUrlPathAndQuery($expect) === self::parseUrlPathAndQuery($payload->aud),
                'email_exact' => function (stdClass $payload, $expect): bool {
                    $expect = is_string($expect) ? [$expect] : $expect;

                    return in_array($payload->email, $expect, true);
                },
                'email_match' => fn (stdClass $payload, string $regex): bool => (bool) preg_match($regex, $payload->email),
            ];
        }

        return $all_matchers;
    }

    private static function parseUrlPathAndQuery(string $url): string
    {
        $parts = parse_url($url);

        return ($parts['path'] ?? null).'?'.($parts['query'] ?? null);
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return $this->constraints;
    }

    /**
     * @throws TokenConstraintFailureException
     */
    public function mustMatch(stdClass $token): void
    {
        $failures = [];
        foreach ($this->constraints as $type => $param) {
            $handler = $this->matchers[$type];
            if (!$handler($token, $param)) {
                $failures[] = $type;
            }
        }

        if ($failures !== []) {
            throw new TokenConstraintFailureException($failures);
        }
    }
}
