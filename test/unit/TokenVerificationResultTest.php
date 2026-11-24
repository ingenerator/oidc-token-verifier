<?php

namespace test\unit\Ingenerator\OIDCTokenVerifier;

use Exception;
use Ingenerator\OIDCTokenVerifier\TokenVerificationFailedException;
use Ingenerator\OIDCTokenVerifier\TokenVerificationResult;
use LogicException;
use PHPUnit\Framework\TestCase;
use stdClass;

class TokenVerificationResultTest extends TestCase
{
    public function testItsStaticEnforceThrowsOnFailureResult(): void
    {
        $token_exception = new Exception('Anything');
        $result = TokenVerificationResult::createFailure($token_exception);
        try {
            TokenVerificationResult::enforce($result);
            $this->fail('Should throw');
        } catch (TokenVerificationFailedException $e) {
            $this->assertSame($result, $e->getVerificationResult());
            $this->assertSame($token_exception, $e->getPrevious());
        }
    }

    public function testItsStaticEnforceReturnsSuccessResult(): void
    {
        $result = TokenVerificationResult::createSuccess(new stdClass());
        $this->assertSame($result, TokenVerificationResult::enforce($result));
    }

    public function testItThrowsOnAccessToFailureOnSuccess(): void
    {
        $result = TokenVerificationResult::createSuccess(new stdClass());
        $this->expectException(LogicException::class);
        $result->getFailure();
    }

    public function testItThrowsOnAccessToPayloadOnFailure(): void
    {
        $result = TokenVerificationResult::createFailure(new Exception('Anything'));
        $this->expectException(LogicException::class);
        $result->getPayload();
    }

    public function testItReturnsImmutablePayloadOnSuccess(): void
    {
        $payload = new stdClass();
        $payload->email = 'anyone@foo.com';
        $result = TokenVerificationResult::createSuccess($payload);
        $this->assertEquals($payload, $result->getPayload());
        $this->assertNotSame(
            $payload,
            $result->getPayload(),
            'Should clone payload to prevent external modification'
        );
    }

    public function testItReturnsFailureOnFailure(): void
    {
        $e = new Exception('Literally anything');
        $this->assertSame($e, TokenVerificationResult::createFailure($e)->getFailure());
    }
}
