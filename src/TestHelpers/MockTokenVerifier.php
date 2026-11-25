<?php

declare(strict_types=1);

namespace Ingenerator\OIDCTokenVerifier\TestHelpers;

use BadMethodCallException;
use Exception;
use Ingenerator\OIDCTokenVerifier\TokenConstraintInterface;
use Ingenerator\OIDCTokenVerifier\TokenConstraints;
use Ingenerator\OIDCTokenVerifier\TokenVerificationResult;
use Ingenerator\OIDCTokenVerifier\TokenVerifier;
use PHPUnit\Framework\Assert;

final class MockTokenVerifier implements TokenVerifier
{
    /**
     * @var list<array{string, list<TokenConstraintInterface>}>
     */
    private array $calls = [];

    public static function willFailWith(Exception $e): static
    {
        return new self(TokenVerificationResult::createFailure($e));
    }

    /**
     * @param array<string, mixed> $token_props
     */
    public static function willSucceedWith(array $token_props): static
    {
        $obj = (object) $token_props;

        return new self(TokenVerificationResult::createSuccess($obj));
    }

    public static function notCalled(): static
    {
        return new self(null);
    }

    private function __construct(
        private readonly ?TokenVerificationResult $result,
    ) {
    }

    public function verify(string $token, TokenConstraints $extra_constraints): TokenVerificationResult
    {
        $this->calls[] = [$token, $extra_constraints->toArray()];
        if ($this->result instanceof TokenVerificationResult) {
            return $this->result;
        }

        throw new BadMethodCallException('Unexpected call to '.__METHOD__);
    }

    /**
     * @param list<TokenConstraintInterface> $extra_constraints
     */
    public function assertVerifiedOnce(string $token, array $extra_constraints = []): void
    {
        Assert::assertEquals([[$token, $extra_constraints]], $this->calls);
    }
}
