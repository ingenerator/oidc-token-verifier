<?php

declare(strict_types=1);

namespace test\unit\Ingenerator\OIDCTokenVerifier\Constraint;

use Ingenerator\OIDCTokenVerifier\Constraint\EmailMatchTokenConstraint;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;

final class EmailMatchTokenConstraintTest extends TestCase
{
    #[TestWith(['/^my@service\\.acct$/', true])]
    #[TestWith(['/@service\\.acct$/', true])]
    #[TestWith(['/@prod-services.accts$/', false])]
    public function testItMatchesEmailAgainstTheConfiguredRegex(string $regex, bool $matches): void
    {
        $constraint = new EmailMatchTokenConstraint($regex);

        $this->assertSame($matches, $constraint->matches((object) ['email' => 'my@service.acct']));
    }

    /** @param array<mixed> $payload */
    #[TestWith([[]])]
    #[TestWith([['email' => true]])]
    #[TestWith([['email' => null]])]
    public function testItDoesNotMatchWhenEmailClaimIsMissingOrInvalid(array $payload): void
    {
        $constraint = new EmailMatchTokenConstraint('/@foo.bar$/');

        $this->assertFalse($constraint->matches((object) $payload));
    }
}
