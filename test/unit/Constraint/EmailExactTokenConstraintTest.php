<?php

declare(strict_types=1);

namespace test\unit\Ingenerator\OIDCTokenVerifier\Constraint;

use Ingenerator\OIDCTokenVerifier\Constraint\EmailExactTokenConstraint;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;

final class EmailExactTokenConstraintTest extends TestCase
{
    #[TestWith([true, 'my@service.acct'])]
    #[TestWith([false, 'differ@ent.service'])]
    #[TestWith([true, 'my@service.acct', 'differ@ent.service'])]
    #[TestWith([false, 'an@other.svc', 'differ@ent.service'])]
    #[TestWith([false])]
    public function testItMatchesAnExactEmail(bool $matches, string ...$expect): void
    {
        $constraint = new EmailExactTokenConstraint(...$expect);

        $this->assertSame($matches, $constraint->matches((object) ['email' => 'my@service.acct']));
    }

    /** @param array<mixed> $payload */
    #[TestWith([[]])]
    #[TestWith([['email' => true]])]
    #[TestWith([['email' => null]])]
    public function testItDoesNotMatchWhenEmailClaimIsMissingOrInvalid(array $payload): void
    {
        $constraint = new EmailExactTokenConstraint('any@mail.net');

        $this->assertFalse($constraint->matches((object) $payload));
    }
}
