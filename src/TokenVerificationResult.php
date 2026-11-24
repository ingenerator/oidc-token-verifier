<?php

namespace Ingenerator\OIDCTokenVerifier;

use Exception;
use LogicException;
use stdClass;

final class TokenVerificationResult
{
    private function __construct(
        private readonly bool $is_verified,
        private readonly ?stdClass $payload,
        private readonly ?Exception $failure,
    ) {
    }

    /**
     * @internal
     */
    public static function createSuccess(stdClass $payload): static
    {
        return new self(true, $payload, null);
    }

    /**
     * @internal
     */
    public static function createFailure(Exception $e): static
    {
        return new self(false, null, $e);
    }

    /**
     * Syntax sugar to ensure that a token was successfully verified before proceeding.
     *
     * As standard the verifier returns a result and you should e.g. do `if ($result->isVerified())`
     * around the protected code. For some implementations it may be simpler to throw an exception.
     * This method helps with that, it will throw if the verification failed or return the result if
     * not.
     *
     * E.g.
     *
     *     $result = TokenVerificationResult::enforce($token_verifier->verify($token));
     *     // If the token cannot be verified an exception is thrown
     *     mail($result->getPayload()->email, 'You were verified');
     *
     * @throws TokenVerificationFailedException if the verification failed
     */
    public static function enforce(TokenVerificationResult $result): TokenVerificationResult
    {
        if (!$result->isVerified()) {
            throw new TokenVerificationFailedException($result);
        }

        return $result;
    }

    public function isVerified(): bool
    {
        return $this->is_verified;
    }

    /**
     * @throws LogicException if the verification failed
     */
    public function getPayload(): stdClass
    {
        if ($this->is_verified) {
            return clone $this->payload;
        }
        throw new LogicException('Cannot access payload on failed token verification');
    }

    /**
     * @throws LogicException if the verification was successful
     */
    public function getFailure(): Exception
    {
        if ($this->is_verified) {
            throw new LogicException('Cannot access failure on successful token verification');
        }

        return $this->failure;
    }
}
