<?php

declare(strict_types=1);

namespace test\unit\Ingenerator\OIDCTokenVerifier\Constraint;

use Ingenerator\OIDCTokenVerifier\Constraint\AudienceExactTokenConstraint;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;

final class AudienceExactTokenConstraintTest extends TestCase
{
    #[TestWith(['https://my-site.com/handler', true])]
    #[TestWith(['https://someone-elses-site.com/handler', false])]
    public function testItMatchesOnlyTheExactAudience(string $expect, bool $matches): void
    {
        $constraint = new AudienceExactTokenConstraint('https://my-site.com/handler');
        $payload = (object) ['aud' => $expect];

        $this->assertSame($matches, $constraint->matches($payload));
    }

    /** @param array<mixed> $payload */
    #[TestWith([[]])]
    #[TestWith([['aud' => true]])]
    #[TestWith([['aud' => null]])]
    public function testItDoesNotMatchWhenAudienceClaimIsMissingOrInvalid(array $payload): void
    {
        $this->assertFalse(new AudienceExactTokenConstraint('https://some.site/foo')->matches((object) $payload));
    }
}
