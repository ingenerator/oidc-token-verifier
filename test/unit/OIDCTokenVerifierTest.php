<?php


namespace test\unit\Ingenerator\OIDCTokenVerifier;


use Ingenerator\OIDCTokenVerifier\OIDCTokenVerifier;
use Ingenerator\OIDCTokenVerifier\TokenVerifier;
use PHPUnit\Framework\TestCase;

class OIDCTokenVerifierTest extends TestCase
{

    public function test_it_is_initialisable()
    {
        $subject = $this->newSubject();
        $this->assertInstanceOf(OIDCTokenVerifier::class, $subject);
        $this->assertInstanceOf(TokenVerifier::class, $subject);
    }

    protected function newSubject(): OIDCTokenVerifier
    {
        return new OIDCTokenVerifier;
    }
}
