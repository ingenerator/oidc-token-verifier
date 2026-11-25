<?php

declare(strict_types=1);

namespace test\unit\Ingenerator\OIDCTokenVerifier\Constraint;

use Ingenerator\OIDCTokenVerifier\Constraint\AudiencePathAndQueryTokenConstraint;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;

final class AudiencePathAndQueryTokenConstraintTest extends TestCase
{
    #[TestWith(['https://my.site/handler', 'https://my.site/handler', true])]
    #[TestWith(['https://my.site/handler?foo=bar&baz=boo', 'https://my.site/handler?foo=bar&baz=boo', true])]
    #[TestWith(['https://my.site/handler?foo=bar&baz=boo', 'http://my.site/handler?foo=bar&baz=boo', true])]
    #[TestWith(['https://my.site/handler?foo=bar&baz=boo', 'http://internal.host/handler?foo=bar&baz=boo', true])]
    #[TestWith(['https://my.site/', 'http://my.site/', true])]
    #[TestWith(['https://my.site/handler', 'https://my.site/anything', false])]
    #[TestWith(['https://my.site/handler?foo=bar&baz=boo', 'http://my.site/handler', false])]
    #[TestWith(['https://my.site/handler?foo=bar&baz=boo', 'http://my.site/handler?other=query', false])]
    #[TestWith(['https://my.site/handler?foo=bar&baz=boo', 'http://my.site/wrong?foo=bar&baz=boo', false])]
    #[TestWith(['https://my.site/handler?foo=bar&baz=boo', 'http://my.site/handler?baz=boo&foo=bar', false])]
    #[TestWith(['https://my.site/', 'http://my.site/handler', false])]
    #[TestWith(['https://any.thing', 'wierd corrupt url', false])]
    public function testItMatchesWhenPathAndQueryAreTheSame(string $expect, string $audience, bool $matches): void
    {
        $constraint = new AudiencePathAndQueryTokenConstraint($expect);

        $this->assertSame($matches, $constraint->matches((object) ['aud' => $audience]));
    }

    /** @param array<mixed> $payload */
    #[TestWith([[]])]
    #[TestWith([['aud' => true]])]
    #[TestWith([['aud' => null]])]
    public function testItDoesNotMatchWhenAudienceClaimIsMissingOrInvalid(array $payload): void
    {
        $constraint = new AudiencePathAndQueryTokenConstraint('https://some.site/foo');

        $this->assertFalse($constraint->matches((object) $payload));
    }
}
