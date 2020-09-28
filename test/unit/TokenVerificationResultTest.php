<?php


namespace test\unit\Ingenerator\OIDCTokenVerifier;


use Ingenerator\OIDCTokenVerifier\TokenVerificationFailedException;
use Ingenerator\OIDCTokenVerifier\TokenVerificationResult;
use PHPUnit\Framework\TestCase;

class TokenVerificationResultTest extends TestCase
{

    public function test_its_static_enforce_throws_on_failure_result()
    {
        $token_exception = new \Exception('Anything');
        $result          = TokenVerificationResult::createFailure($token_exception);
        try {
            TokenVerificationResult::enforce($result);
            $this->fail('Should throw');
        } catch (TokenVerificationFailedException $e) {
            $this->assertSame($result, $e->getVerificationResult());
            $this->assertSame($token_exception, $e->getPrevious());
        }
    }

    public function test_its_static_enforce_returns_success_result()
    {
        $result = TokenVerificationResult::createSuccess(new \stdClass);
        $this->assertSame($result, TokenVerificationResult::enforce($result));
    }

    public function test_it_throws_on_access_to_failure_on_success()
    {
        $result = TokenVerificationResult::createSuccess(new \stdClass);
        $this->expectException(\LogicException::class);
        $result->getFailure();
    }

    public function test_it_throws_on_access_to_payload_on_failure()
    {
        $result = TokenVerificationResult::createFailure(new \Exception('Anything'));
        $this->expectException(\LogicException::class);
        $result->getPayload();
    }

    public function test_it_returns_immutable_payload_on_success()
    {
        $payload = new \stdClass;
        $payload->email = 'anyone@foo.com';
        $result = TokenVerificationResult::createSuccess($payload);
        $this->assertEquals($payload, $result->getPayload());
        $this->assertNotSame(
            $payload,
            $result->getPayload(),
            'Should clone payload to prevent external modification'
        );
    }

    public function test_it_returns_failure_on_failure()
    {
        $e = new \Exception('Literally anything');
        $this->assertSame($e, TokenVerificationResult::createFailure($e)->getFailure());
    }

}
