<?php

declare(strict_types=1);

namespace Ingenerator\OIDCTokenVerifier;

use stdClass;

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
final class TokenConstraints
{
    /**
     * @var list<TokenConstraintInterface>
     */
    private array $constraints = [];

    /**
     * An empty constraints object that will only check the signature is valid.
     *
     * *ONLY* use this in production code if you are separately validating the email address and/or audience of the
     * token in your own code (see class docs).
     */
    public static function signatureCheckOnly(): TokenConstraints
    {
        return new self();
    }

    public function __construct(TokenConstraintInterface ...$constraints)
    {
        $this->constraints = array_values($constraints);
    }

    /**
     * @return list<TokenConstraintInterface>
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
        foreach ($this->constraints as $constraint) {
            if (!$constraint->matches($token)) {
                $failures[] = $constraint->name;
            }
        }

        if ($failures !== []) {
            throw new TokenConstraintFailureException($failures);
        }
    }
}
