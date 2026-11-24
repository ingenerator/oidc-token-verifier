<?php

namespace Ingenerator\OIDCTokenVerifier\TestHelpers;

use BadMethodCallException;
use Exception;
use Ingenerator\OIDCTokenVerifier\TokenConstraints;
use Ingenerator\OIDCTokenVerifier\TokenVerificationResult;
use Ingenerator\OIDCTokenVerifier\TokenVerifier;
use PHPUnit\Framework\Assert;

class MockTokenVerifier implements TokenVerifier
{
    protected $calls = [];

    public static function willFailWith(Exception $e): static
    {
        return new static(TokenVerificationResult::createFailure($e));
    }

    public static function willSucceedWith(array $token_props): static
    {
        $obj = (object) $token_props;

        return new static(TokenVerificationResult::createSuccess($obj));
    }

    public static function notCalled(): static
    {
        return new static(null);
    }

    protected function __construct(
        protected ?TokenVerificationResult $result,
    ) {
    }

    public function verify(string $token, TokenConstraints $extra_constraints): TokenVerificationResult
    {
        $this->calls[] = [$token, $extra_constraints->toArray()];
        if ($this->result) {
            return $this->result;
        }

        throw new BadMethodCallException('Unexpected call to '.__METHOD__);
    }

    public function assertVerifiedOnce(string $token, array $extra_constraints = []): void
    {
        Assert::assertSame([[$token, $extra_constraints]], $this->calls);
    }
}
