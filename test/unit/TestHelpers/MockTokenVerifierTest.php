<?php

declare(strict_types=1);

namespace test\unit\Ingenerator\OIDCTokenVerifier\TestHelpers;

use Ingenerator\OIDCTokenVerifier\Constraint\AudienceExactTokenConstraint;
use Ingenerator\OIDCTokenVerifier\TestHelpers\MockTokenVerifier;
use Ingenerator\OIDCTokenVerifier\TokenConstraints;
use PHPUnit\Framework\TestCase;

final class MockTokenVerifierTest extends TestCase
{
    public function testItAssertsConstraintObjectsByValue(): void
    {
        $verifier = MockTokenVerifier::willSucceedWith([]);
        $verifier->verify('jwt', new TokenConstraints(new AudienceExactTokenConstraint('https://example.test')));

        $verifier->assertVerifiedOnce('jwt', [new AudienceExactTokenConstraint('https://example.test')]);
    }
}
