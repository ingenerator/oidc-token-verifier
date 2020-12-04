<?php


namespace test\unit\Ingenerator\OIDCTokenVerifier;


use Ingenerator\OIDCTokenVerifier\TokenConstraintFailureException;
use Ingenerator\OIDCTokenVerifier\TokenConstraints;
use PHPUnit\Framework\TestCase;

class TokenConstraintsTest extends TestCase
{

    public function test_it_is_initialisable()
    {
        $this->assertInstanceOf(TokenConstraints::class, new TokenConstraints([]));
    }

    public function test_its_signature_check_only_constructor_matches_any_token()
    {
        $this->assertConstraintValidation(TRUE, NULL, TokenConstraints::signatureCheckOnly(), new \stdClass);
    }

    public function test_it_throws_on_construction_with_unknown_constraint_type()
    {
        $this->expectException(\InvalidArgumentException::class);
        new TokenConstraints(['not-a-constraint' => 'whatever']);
    }

    /**
     * @testWith ["https://someone-elses-site.com/handler", false, "[audience_exact]"]
     *            ["https://my-site.com/handler", true, null]
     */
    public function test_it_can_validate_exact_audience_match($constraint, $expect_valid, $expect_msg)
    {
        $subject    = new TokenConstraints(["audience_exact" => $constraint]);
        $token      = new \stdClass;
        $token->aud = "https://my-site.com/handler";
        $this->assertConstraintValidation($expect_valid, $expect_msg, $subject, $token);
    }

    /**
     * @testWith ["my@service.acct", true, null]
     *           ["differ@ent.service", false, "[email_exact]"]
     *           [["my@service.acct"], true, null]
     *           [["my@service.acct", "differ@ent.service"], true, null]
     *           [["an@other.svc", "differ@ent.service"], false, "[email_exact]"]
     */
    public function test_it_can_validate_exact_email_match_against_list($constraint, $expect_valid, $expect_msg)
    {
        $subject      = new TokenConstraints(["email_exact" => $constraint]);
        $token        = new \stdClass;
        $token->email = "my@service.acct";
        $this->assertConstraintValidation($expect_valid, $expect_msg, $subject, $token);
    }

    /**
     * @testWith ["/^my@service\\.acct$/", true, null]
     *           ["/@service\\.acct$/", true, null]
     *           ["/@prod-services.accts$/", false, "[email_match]"]
     */
    public function test_it_can_validate_email_begins_with($constraint, $expect_valid, $expect_msg)
    {
        $subject      = new TokenConstraints(["email_match" => $constraint]);
        $token        = new \stdClass;
        $token->email = "my@service.acct";
        $this->assertConstraintValidation($expect_valid, $expect_msg, $subject, $token);
    }

    /**
     * @testWith [{"email_exact": "foo@acct.test", "audience_exact": "http://foo.bar/com"}, true, null]
     *           [{"email_exact": "bar@acct.test", "audience_exact": "http://foo.bar/com"}, false, "[email_exact]"]
     *           [{"email_exact": "foo@acct.test", "audience_exact": "http://bar.com/"}, false, "[audience_exact]"]
     *           [{"email_exact": "bar@acct.test", "audience_exact": "http://bar.com/"}, false, "[audience_exact, email_exact]"]
     */
    public function test_it_validates_multiple_constraints_and_requires_all_to_pass(
        $contraints,
        $expect_valid,
        $expect_msg
    ) {
        $subject      = new TokenConstraints($contraints);
        $token        = new \stdClass;
        $token->aud   = 'http://foo.bar/com';
        $token->email = 'foo@acct.test';
        $this->assertConstraintValidation($expect_valid, $expect_msg, $subject, $token);
    }

    public function test_its_to_array_returns_input_constraints()
    {
        $constraints = ['email_exact' => ['foo@bar.com', 'bil@bar.com'], 'audience_exact' => 'http://fo.bar'];
        $subject     = new TokenConstraints($constraints);
        $this->assertSame($constraints, $subject->toArray());
    }

    private function assertConstraintValidation(
        bool $expect_valid,
        ?string $expect_msg,
        TokenConstraints $subject,
        \stdClass $token
    ): void {
        if ( ! $expect_valid) {
            $this->expectException(TokenConstraintFailureException::class);
            $this->expectErrorMessage($expect_msg);
        }

        $subject->mustMatch($token);

        if ($expect_valid) {
            $this->assertTrue(TRUE, 'Token was valid');
        }
    }
}
