<?php

declare(strict_types=1);

namespace test\unit\Ingenerator\OIDCTokenVerifier;

use Ingenerator\OIDCTokenVerifier\Constraint\AudienceExactTokenConstraint;
use Ingenerator\OIDCTokenVerifier\Constraint\EmailExactTokenConstraint;
use Ingenerator\OIDCTokenVerifier\Constraint\MatchAnyTokenConstraint;
use Ingenerator\OIDCTokenVerifier\TokenConstraintFailureException;
use Ingenerator\OIDCTokenVerifier\TokenConstraintInterface;
use Ingenerator\OIDCTokenVerifier\TokenConstraints;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use stdClass;

final class TokenConstraintsTest extends TestCase
{
    public function testItIsInitialisableWithAListOfConstraints(): void
    {
        $constraint = new AudienceExactTokenConstraint('https://my-site.com/handler');
        $subject = new TokenConstraints($constraint);

        $this->assertInstanceOf(TokenConstraints::class, $subject);
        $this->assertSame([$constraint], $subject->toArray());
    }

    public function testItsSignatureCheckOnlyConstructorMatchesAnyToken(): void
    {
        $constraints = TokenConstraints::signatureCheckOnly();

        $this->assertEquals([new MatchAnyTokenConstraint()], $constraints->toArray());
        $constraints->mustMatch(new stdClass());
    }

    /**
     * @return iterable<string, array{stdClass, string|null}>
     */
    public static function constraintMatchCases(): iterable
    {
        yield 'matches none' => [
            (object) ['aud' => 'https://other.example', 'email' => 'other@example.test'],
            'Token did not match constraints: [audience_exact, email_exact]',
        ];

        yield 'matches first only' => [
            (object) ['aud' => 'https://expected.example', 'email' => 'other@example.test'],
            'Token did not match constraints: [email_exact]',
        ];

        yield 'matches last only' => [
            (object) ['aud' => 'https://other.example', 'email' => 'expected@example.test'],
            'Token did not match constraints: [audience_exact]',
        ];

        yield 'matches both' => [
            (object) ['aud' => 'https://expected.example', 'email' => 'expected@example.test'],
            null,
        ];
    }

    #[DataProvider('constraintMatchCases')]
    public function testItRequiresEveryConstraintToMatchAndReportsFailingNames(
        stdClass $token,
        ?string $expected_message,
    ): void {
        $constraints = new TokenConstraints(
            new AudienceExactTokenConstraint('https://expected.example'),
            new EmailExactTokenConstraint('expected@example.test'),
        );

        if ($expected_message === null) {
            $constraints->mustMatch($token);
            /* @phpstan-ignore method.alreadyNarrowedType (just need an assertion to show phpunit we asserted) */
            $this->assertTrue(true, 'Should not throw');
        } else {
            $this->assertConstraintsFailWithMessage($constraints, $token, $expected_message);
        }
    }

    public function testItReportsAllFailingConstraintNamesInDeterministicOrder(): void
    {
        $constraints = new TokenConstraints(
            new EmailExactTokenConstraint('expected@example.test'),
            new AudienceExactTokenConstraint('https://expected.example'),
        );

        $this->assertConstraintsFailWithMessage(
            $constraints,
            (object) [
                'aud' => 'https://other.example',
                'email' => 'other@example.test',
            ],
            'Token did not match constraints: [audience_exact, email_exact]',
        );
    }

    public function testItEvaluatesRepeatedConstraintNamesAndReportsEachFailure(): void
    {
        $constraint = new class implements TokenConstraintInterface {
            public static int $calls = 0;

            public string $name { get => 'always_fail'; }

            public function matches(stdClass $payload): bool
            {
                ++self::$calls;

                return false;
            }
        };
        $constraint::class::$calls = 0;
        $another_constraint = new ($constraint::class)();

        $this->assertConstraintsFailWithMessage(
            new TokenConstraints($constraint, $another_constraint),
            new stdClass(),
            'Token did not match constraints: [always_fail, always_fail]',
        );
        $this->assertSame(2, $constraint::class::$calls);
    }

    public function testItSupportsCustomConstraints(): void
    {
        $constraint = new class implements TokenConstraintInterface {
            public string $name { get => 'custom_claim'; }

            public function matches(stdClass $payload): bool
            {
                return ($payload->custom_claim ?? null) === 'allowed';
            }
        };
        $constraints = new TokenConstraints($constraint);

        $this->assertSame([$constraint], $constraints->toArray());
        $constraints->mustMatch((object) ['custom_claim' => 'allowed']);
        $this->assertConstraintsFailWithMessage(
            $constraints,
            (object) ['custom_claim' => 'not allowed'],
            'Token did not match constraints: [custom_claim]',
        );
    }

    private function assertConstraintsFailWithMessage(
        TokenConstraints $constraints,
        stdClass $token,
        string $message,
    ): void {
        try {
            $constraints->mustMatch($token);
            $this->fail('Expected constraints to fail');
        } catch (TokenConstraintFailureException $e) {
            $this->assertSame($message, $e->getMessage());
        }
    }
}
