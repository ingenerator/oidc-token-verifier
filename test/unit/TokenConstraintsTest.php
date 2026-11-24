<?php

declare(strict_types=1);

namespace test\unit\Ingenerator\OIDCTokenVerifier;

use Ingenerator\OIDCTokenVerifier\TokenConstraintFailureException;
use Ingenerator\OIDCTokenVerifier\TokenConstraints;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;
use stdClass;

final class TokenConstraintsTest extends TestCase
{
    public function testItIsInitialisable(): void
    {
        $this->assertInstanceOf(TokenConstraints::class, new TokenConstraints([]));
    }

    public function testItsSignatureCheckOnlyConstructorMatchesAnyToken(): void
    {
        $this->assertConstraintValidation(true, null, TokenConstraints::signatureCheckOnly(), new stdClass());
    }

    public function testItThrowsOnConstructionWithUnknownConstraintType(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new TokenConstraints(['not-a-constraint' => 'whatever']);
    }

    #[TestWith(['https://someone-elses-site.com/handler', false, '[audience_exact]'])]
    #[TestWith(['https://my-site.com/handler', true, null])]
    public function testItCanValidateExactAudienceMatch(
        string $constraint,
        bool $expect_valid,
        ?string $expect_msg,
    ): void {
        $subject = new TokenConstraints(['audience_exact' => $constraint]);
        $token = new stdClass();
        $token->aud = 'https://my-site.com/handler';
        $this->assertConstraintValidation($expect_valid, $expect_msg, $subject, $token);
    }

    #[TestWith(['https://my.site/handler', 'https://my.site/handler', true, null])]
    #[TestWith(['https://my.site/handler?foo=bar&baz=boo', 'https://my.site/handler?foo=bar&baz=boo', true, null])]
    #[TestWith(['https://my.site/handler?foo=bar&baz=boo', 'http://my.site/handler?foo=bar&baz=boo', true, null])]
    #[TestWith(['https://my.site/handler?foo=bar&baz=boo', 'http://internal.host/handler?foo=bar&baz=boo', true, null])]
    #[TestWith(['https://my.site/anything', 'http://my.site/handler', false, '[audience_path_and_query]'])]
    #[TestWith(['https://my.site/h?foo=bar&baz=boo', 'http://my.site/h', false, '[audience_path_and_query]'])]
    #[TestWith([
        'https://my.site/h?foo=bar&baz=boo',
        'http://my.site/h?other=query',
        false,
        '[audience_path_and_query]',
    ])]
    #[TestWith([
        'https://my.site/h?foo=bar&baz=boo',
        'http://my.site/wrong?foo=bar&baz=boo',
        false,
        '[audience_path_and_query]',
    ])]
    #[TestWith([
        'https://my.site/h?foo=bar&baz=boo',
        'http://my.site/h?baz=boo&foo=bar',
        false,
        '[audience_path_and_query]',
    ])]
    #[TestWith(['https://my.site/', 'http://my.site/', true, null])]
    #[TestWith(['https://my.site/', 'http://my.site/h', false, '[audience_path_and_query]'])]
    #[TestWith(['https://any.thing', 'wierd corrupt url', false, '[audience_path_and_query]'])]
    public function testItCanValidateAudiencePathAndQuery(
        string $constraint,
        string $audience,
        bool $expect_valid,
        ?string $expect_msg,
    ): void {
        $subject = new TokenConstraints(['audience_path_and_query' => $constraint]);
        $token = new stdClass();
        $token->aud = $audience;
        $this->assertConstraintValidation($expect_valid, $expect_msg, $subject, $token);
    }

    /** @param string|list<string> $constraint */
    #[TestWith(['my@service.acct', true, null])]
    #[TestWith(['differ@ent.service', false, '[email_exact]'])]
    #[TestWith([['my@service.acct'], true, null])]
    #[TestWith([['my@service.acct', 'differ@ent.service'], true, null])]
    #[TestWith([['an@other.svc', 'differ@ent.service'], false, '[email_exact]'])]
    public function testItCanValidateExactEmailMatchAgainstList(
        string|array $constraint,
        bool $expect_valid,
        ?string $expect_msg,
    ): void {
        $subject = new TokenConstraints(['email_exact' => $constraint]);
        $token = new stdClass();
        $token->email = 'my@service.acct';
        $this->assertConstraintValidation($expect_valid, $expect_msg, $subject, $token);
    }

    #[TestWith(['/^my@service\\.acct$/', true, null])]
    #[TestWith(['/@service\\.acct$/', true, null])]
    #[TestWith(['/@prod-services.accts$/', false, '[email_match]'])]
    public function testItCanValidateEmailBeginsWith(
        string $constraint,
        bool $expect_valid,
        ?string $expect_msg,
    ): void {
        $subject = new TokenConstraints(['email_match' => $constraint]);
        $token = new stdClass();
        $token->email = 'my@service.acct';
        $this->assertConstraintValidation($expect_valid, $expect_msg, $subject, $token);
    }

    /**
     * @param array<string, string|list<string>> $contraints
     */
    #[TestWith([['email_exact' => 'foo@acct.test', 'audience_exact' => 'http://foo.bar/com'], true, null])]
    #[TestWith([['email_exact' => 'bar@acct.test', 'audience_exact' => 'http://foo.bar/com'], false, '[email_exact]'])]
    #[TestWith([['email_exact' => 'foo@acct.test', 'audience_exact' => 'http://bar.com/'], false, '[audience_exact]'])]
    #[TestWith([['email_exact' => 'bar@acct.test', 'audience_exact' => 'http://bar.com/'], false, '[audience_exact, email_exact]'])]
    public function testItValidatesMultipleConstraintsAndRequiresAllToPass(
        array $contraints,
        bool $expect_valid,
        ?string $expect_msg,
    ): void {
        $subject = new TokenConstraints($contraints);
        $token = new stdClass();
        $token->aud = 'http://foo.bar/com';
        $token->email = 'foo@acct.test';
        $this->assertConstraintValidation($expect_valid, $expect_msg, $subject, $token);
    }

    public function testItsToArrayReturnsInputConstraints(): void
    {
        $constraints = ['email_exact' => ['foo@bar.com', 'bil@bar.com'], 'audience_exact' => 'http://fo.bar'];
        $subject = new TokenConstraints($constraints);
        $this->assertSame($constraints, $subject->toArray());
    }

    private function assertConstraintValidation(
        bool $expect_valid,
        ?string $expect_msg,
        TokenConstraints $subject,
        stdClass $token,
    ): void {
        try {
            $subject->mustMatch($token);
        } catch (TokenConstraintFailureException $e) {
        }

        if ($expect_valid) {
            $this->assertFalse(isset($e), 'Token should be valid - should not get exception');
        } else {
            $this->assertTrue(isset($e), 'Token should be invalid - should get exception');
            $this->assertStringContainsString($expect_msg, $e->getMessage());
        }
    }
}
