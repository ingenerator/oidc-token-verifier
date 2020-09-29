<?php


namespace test\unit\Ingenerator\OIDCTokenVerifier;


use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use Ingenerator\OIDCTokenVerifier\ArrayCertificateProvider;
use Ingenerator\OIDCTokenVerifier\CertificateDiscoveryFailedException;
use Ingenerator\OIDCTokenVerifier\OIDCTokenVerifier;
use Ingenerator\OIDCTokenVerifier\TokenVerificationResult;
use Ingenerator\OIDCTokenVerifier\TokenVerifier;
use PHPUnit\Framework\TestCase;

class OIDCTokenVerifierTest extends TestCase
{
    protected static $keys = [
        '2f42' => [
            'kid'     => "a76bef64925480605b2de8598174ab57f4852f42",
            'public'  => "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7KibSE6/1DvFaIyscI1D\neTovN2NvxLHyP42UrlA1Ock2uacZa9B0nVWc106WrIDnL8KXFubFSAG4MuZhkW7N\nmtqeEkNjWWQlu4NO7pFQx22vhOsI9Yr2+bmlXyZuwfHwdG35LHxuLoYW5X7PM0dJ\nXIa/ZyZEtxa5QQAwwHF0lULn6S5tMn4PGaQDTIw70q/dpB3lOZDyXMX5AUZ6Qfbf\n+64aCLdwJLEr9jKDrP+P7SjBfVxXSCicPVPhRAf2zXEuY+thqyiuvr4EkszSr25G\nuAA9W5aDbAWjuUndyiSDjt9KIAD0N+FFFpxZBiUKCGnqJG2yg33O9taJn/KzCnOk\njwIDAQAB\n-----END PUBLIC KEY-----\n",
            'private' => "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDsqJtITr/UO8Vo\njKxwjUN5Oi83Y2/EsfI/jZSuUDU5yTa5pxlr0HSdVZzXTpasgOcvwpcW5sVIAbgy\n5mGRbs2a2p4SQ2NZZCW7g07ukVDHba+E6wj1ivb5uaVfJm7B8fB0bfksfG4uhhbl\nfs8zR0lchr9nJkS3FrlBADDAcXSVQufpLm0yfg8ZpANMjDvSr92kHeU5kPJcxfkB\nRnpB9t/7rhoIt3AksSv2MoOs/4/tKMF9XFdIKJw9U+FEB/bNcS5j62GrKK6+vgSS\nzNKvbka4AD1bloNsBaO5Sd3KJIOO30ogAPQ34UUWnFkGJQoIaeokbbKDfc721omf\n8rMKc6SPAgMBAAECggEAHuKuSVSFsoQOcmORiarV+HdAfEEM8CWtEOBAXDN5js4U\nx0vohGqTHYlzy6GlBmRYR6Jkp4d8jbYzvOjWKO3GBYSshoOm7p6kUgGEBpyOZ0iI\nVJd79teo/dRdobpZUBRsJjXIBCdFFetIB7FyByYxi9LGHgcfhql/id0lf6gO5/+w\nFtFeIzbO4mSEetBMJIiiH7jKrGu+ypOMSEER8aevRrJy73vSxCSp1JXMe0QidVMl\nWX4u95iFE/U5YR3b07KKFQxJT2+JUwq1HkwasndTmLp7FfrE+bydooSnQ2VglRnE\nn1XLMMZG13UGgaxTN0K9rOwxMPJOJBO9HGcUPdndeQKBgQD4Lhd9RGWCiNJ3LuZA\nUz+fhyJZk14T9UqxhOE/8ocG4J/Otji6OVXFWo6cHw4zn2nB7aMYnXRtWpQcSX0q\n8ncQkVccLuGvJmUyXCIX1bxnKp41YOt524a5cc7Mk0mEz68J4YWof/+qp9lCs/Vo\nfysFNYsSp4DQu27oEkKEIrV3bQKBgQD0HZQzKurXastLqhdkcOYPtaIhNUlPiKo3\nHpxqJfawelWhfuPPZEP3MoDxbgSVo0VWpD2Gr/yvkydKbk7n8addI5dnSTCOrZEt\nLHvUAVpLEBbhQ7vrd/btawAOqy2a+PHiDE4GOzwJThx+AtgOYLDA91RrNN5XU0Nw\nV7eG549iawKBgB0dCxRe2amec1IX5lrVaTlFmPn5F6gvtjts4x+lS8G6yARvy+fM\nogssvF4EJp5XrQha4C8bCXVqksVeuZg4KU+APT/JICBz2Js3w6gYIqnXjgek/vqk\njgFjIGdPP+iclGQMWKmTmmJinlH82mUPxfQue8oMbEgQNMp0mej2SWNhAoGAXH3k\ni+qD5jC5bCa7DDxWfrdEAa8N4suWKqI3g2R07nK7hR/tssN7mOqSvmb/565f9C7w\nfNqrM97ecS4QSYNe9UQp9mFdu4F50xLaq/4DNxOWh61BQztF3LjA4c3rzp7qDsq4\nuVWyLphg5UGwmOn7rnFHlAMJBy8uCx/BEqUjx5cCgYEArsVP+Odjbasckmkhwx0q\nMCbKgFMOn2bfxd24x+6rhsxQMUiArYXlEOcFtjuTC+wRvqgSf+JE3HLytp2u3Hj+\nD2zDyJK8pSRtcnBC6HMgZlHYOWO2nI5nb2fahN3UXPw7AFdKUcVK0lYFVD5/aFsa\nxtSUhSizYz8XA9Um6ucJL68=\n-----END PRIVATE KEY-----\n"
        ],
        'e762' => [
            'kid'     => "7805d97db03669f8a1df1044661df53bb3dce762",
            'public'  => "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqRWSu8hGrphVqYrvauDf\nhqiXBE+xovY1D+SdQq26+C/XHHltVXOCyp/T8oRqe/kWYLZTA4Fn8EmZpU4IKFli\nT9e0GzOpWbjTpKWSKznZFDoR5ZRZkGvPEwDuKY8xfyiA9+I5xCHTdyWgL8pyhcv5\nneMrWDkVaVg763OZsp9MTHsSR3sSYXm0oSJzxduW6OF28T6yHw1/0s9UiBY/Itf+\nQXAUn74kUyrgcb5wTAWKCoxNLd5IcddFFrs+ij6Jx09xZ8YvzBhmKa4nOC0h//uu\nwzMzQrMj9U8GcAwrESVc+Fuj13aEjkz2yI6H758i/oVzvqwJ7EogxWkaZBVmlHgi\nUwIDAQAB\n-----END PUBLIC KEY-----\n",
            'private' => "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCpFZK7yEaumFWp\niu9q4N+GqJcET7Gi9jUP5J1Crbr4L9cceW1Vc4LKn9PyhGp7+RZgtlMDgWfwSZml\nTggoWWJP17QbM6lZuNOkpZIrOdkUOhHllFmQa88TAO4pjzF/KID34jnEIdN3JaAv\nynKFy/md4ytYORVpWDvrc5myn0xMexJHexJhebShInPF25bo4XbxPrIfDX/Sz1SI\nFj8i1/5BcBSfviRTKuBxvnBMBYoKjE0t3khx10UWuz6KPonHT3Fnxi/MGGYpric4\nLSH/+67DMzNCsyP1TwZwDCsRJVz4W6PXdoSOTPbIjofvnyL+hXO+rAnsSiDFaRpk\nFWaUeCJTAgMBAAECggEANKhNTEHxEUrL0sM8ELL7qfozHdqb3b6Dg/GUsEFeqxBr\nE6kVTbltkCD6ZtqqNvW57GCbtcnFTuX8/agxji9YGLl6k8YhBZoz/2C5BtE7M7tp\n+2+Z/Qo2MRrnEPZRWeKJV6mSh+xo6QBExN1tkRGXKX6n7w/IBUi/UHJt+Vz27BIe\nUQnrJesDyGRp8NTmjJShXrQTpqzTu6lTyCWDugHXlCI7iVqDJnkOaQEZICi5qz0s\nHZnMav7BFRqtcqXcy6bgesivmx+8shk1jCFRgN/A7ZMMX02HSGIDKbaQLeEBBnHe\nmzjo+BqsMIS90JvwdiZ/tB1dwrIuGcY0MNkGf4SsMQKBgQDXtTilZfmhidSAXSUu\nuJ1DxWttObWMd+hbiZPouSDxgppfpIUHHrmsea54CWWiDP9KspfcKEwcvgUt/85+\nuEwKd1zCp8mMyZ7bq3fBLXW7sw9TbgYYfAygmGSrPJhwS2wijL0DPxUnlyKlvL1C\nwupsNPDwR8xGET0rg4N9ZLe7hwKBgQDIquQGlaADMbE1/v2bq8YYL/I+3alMba2b\nyDt/O8NsGL6VAJDVJXA2rXA/SYzX3FoRks584lN9ylPY1XPjZ3g/9cpnJhJ+vhUR\nvDwxjvOaCswTLUew6k330dzoge2kz9GQh8OplZzzjWybXWFy1TGLtQPzYtFhPTx9\nefqm7aLN1QKBgENKCO2vrfuyX1PbuqmkdYqanzRneDblgNptRHKorZopP7buP4FF\nGG6xVrejVs0CePD4XV8UQwoETOFYlzX4j+AD9C/U347HpoKoLqdYYw22geVowQYK\nTHYck+rG8Fa3cHgmpx/IIfVDtE83XWLiIva2XSLXguWoowhb8jy/moEpAoGBAIjE\nCFQAiKWEqc4uc7U01vfHPejg9LFVk1y4lOx71A6JsuMlFpFfSeLKRNWtkGPTGEQf\n9cIiE1uJmaoQmUKlU8zr/b5dsX9WmE+VJsV0M82KjFqJovIOT4OXMmP5ofmRdrh1\n/8JGaUmJ2zrs4yz75x/cCMxKToBi1yaCC3bYQfzdAoGANcaAN9lRi7J2GsCq2jr8\nPmvxQm64RcVotmX/7ePjOr0+t8UIkHvwE0b8Kfgah25a+m/43vK2B8qaaqoZQuHb\nZgu+QHF06FCwA8rM4GMNFtd9vEgWM1kYPGPorrWuWGpTlPZFFjr5xgo973WLqwoV\nQKnB4qM3XyFDOMSs/nb/OBo=\n-----END PRIVATE KEY-----\n"
        ]
    ];

    /**
     * @var array
     */
    private $certs = [];

    /**
     * @var string
     */
    private $expected_issuer = 'https://secure.provider';

    public function test_it_is_initialisable()
    {
        $subject = $this->newSubject();
        $this->assertInstanceOf(OIDCTokenVerifier::class, $subject);
        $this->assertInstanceOf(TokenVerifier::class, $subject);
    }

    public function test_it_bubbles_certificate_discovery_exception()
    {
        // This is more likely to be a network / config / system fault than an auth issue
        $this->givenCertProviderWithCerts('https://other.account.provider', ['2f42']);
        $this->expected_issuer = 'https://some.account.provider';
        $token                 = $this->createJwtWithKey(
            ['iss' => 'https://some.account.provider'],
            '2f42'
        );
        $subject               = $this->newSubject();
        $this->expectException(CertificateDiscoveryFailedException::class);
        $subject->verify($token);
    }

    public function test_it_fails_verification_if_key_is_not_present_in_certificates()
    {
        $token = $this->createJwtWithKey(
            ['iss' => 'https://some.account.provider'],
            'e762'
        );
        $this->givenCertProviderWithCerts('https://some.account.provider', ['2f42']);
        $this->expected_issuer = 'https://some.account.provider';

        $subject = $this->newSubject();
        $result  = $subject->verify($token, []);
        $this->assertFalse($result->isVerified(), 'Should not be verified');
        $this->assertStringContainsString(
            'unable to lookup correct key',
            $result->getFailure()->getMessage()
        );
    }

    public function test_it_fails_verification_if_signature_is_not_valid()
    {
        $token                 = $this->createJwtWithKey(
            ['iss' => 'https://some.account.provider'],
            'e762'
        );
        $this->certs           = [
            'https://some.account.provider' => [
                // Cert for the specified key ID is valid but not the one it was signed with
                static::$keys['e762']['kid'] => static::$keys['2f42']['public']
            ]
        ];
        $this->expected_issuer = 'https://some.account.provider';

        $subject = $this->newSubject();
        $result  = $subject->verify($token);
        $this->assertFalse($result->isVerified(), 'Should not be verified');
        $this->assertInstanceOf(SignatureInvalidException::class, $result->getFailure());
    }

    /**
     * @testWith [-200, -100, "/Expired token/"]
     *           [100, 300, "/^Cannot handle token prior to/"]
     */
    public function test_it_fails_verification_if_expired_or_not_yet_valid(
        $iat_offset,
        $exp_offset,
        $expect_reason
    ) {
        $token = $this->createJwtWithKey(
            [
                'iss' => 'https://some.account.provider',
                'iat' => time() + $iat_offset,
                'exp' => time() + $exp_offset
            ],
            'e762'
        );
        $this->givenCertProviderWithCerts('https://some.account.provider', ['e762']);
        $this->expected_issuer = 'https://some.account.provider';

        $subject = $this->newSubject();
        $result  = $subject->verify($token);
        $this->assertFalse($result->isVerified(), 'Should not be verified');
        $this->assertRegExp($expect_reason, $result->getFailure()->getMessage());
    }

    public function test_it_fails_verification_if_payload_issuer_does_not_match_expected_issuer()
    {
        $token = $this->createJwtWithKey(
            [
                'iss' => 'https://somehow.faked.account.provider',
            ],
            'e762'
        );
        $this->givenCertProviderWithCerts('https://some.account.provider', ['e762']);
        $this->expected_issuer = 'https://some.account.provider';

        $subject = $this->newSubject();
        $result  = $subject->verify($token);
        $this->assertFalse($result->isVerified(), 'Should not be verified');
        $this->assertStringContainsString(
            'Mismatched token issuer',
            $result->getFailure()->getMessage()
        );
    }

    /**
     * @testWith ["e762"]
     *           ["2f42"]
     *
     */
    public function test_it_passes_verification_if_issuer_matches_expectations($use_kid)
    {
        $payload = [
            'aud'            => 'https://foo.bar.com/anything',
            'azp'            => 'any-authorized-party-value',
            'email'          => 'my-email-account@wherever.com',
            'email_verified' => 1,
            'exp'            => time() + 3600,
            'iat'            => time(),
            'iss'            => 'https://some.account.provider',
            'sub'            => 'any-user-id'
        ];

        $token = $this->createJwtWithKey($payload, $use_kid);
        $this->givenCertProviderWithCerts('https://some.account.provider', ['e762', '2f42']);
        $this->expected_issuer = 'https://some.account.provider';

        $subject = $this->newSubject();
        $result  = $subject->verify($token);
        $this->assertTrue($result->isVerified(), 'Result should be verified');
        $this->assertSame(
            'https://foo.bar.com/anything',
            $result->getPayload()->aud,
            'Includes payload in result'
        );
        $this->assertSame($payload, \json_decode(\json_encode($result->getPayload()), TRUE));
    }

    /**
     * @testWith ["https://someone-elses-site.com/handler", false]
     *           ["https://my-site.com/handler", true]
     */
    public function test_it_optionally_verifies_audience_matches($aud, $expect)
    {
        $token  = $this->givenTokenThatWillPassBasicVerification(['aud' => $aud]);
        $result = $this->newSubject()->verify(
            $token,
            ['audience_exact' => 'https://my-site.com/handler']
        );
        $this->assertSame($expect, $result->isVerified());
    }

    /**
     * @testWith ["my@service.acct", true]
     *           ["differ@ent.service", false]
     *           [["my@service.acct"], true]
     *           [["my@service.acct", "differ@ent.service"], true]
     *           [["an@other.svc", "differ@ent.service"], false]
     */
    public function test_it_optionally_verifies_email_matches_exact_list($constraint, $expect)
    {
        $token  = $this->givenTokenThatWillPassBasicVerification(['email' => 'my@service.acct']);
        $result = $this->newSubject()->verify(
            $token,
            ['email_exact' => $constraint]
        );
        $this->assertSame($expect, $result->isVerified());
    }

    /**
     * @testWith ["my@service.acct", true]
     *           ["another@service.acct", true]
     *           ["impostor@services.accts", false]
     */
    public function test_it_optionally_verifies_email_matches_pattern($email, $expect)
    {
        $token  = $this->givenTokenThatWillPassBasicVerification(['email' => $email]);
        $result = $this->newSubject()->verify(
            $token,
            ['email_match' => '/\@service\.acct$/']
        );
        $this->assertSame($expect, $result->isVerified());
    }

    public function test_it_throws_if_constraint_is_not_defined()
    {
        $token   = $this->givenTokenThatWillPassBasicVerification([]);
        $subject = $this->newSubject();
        $this->expectException(\InvalidArgumentException::class);
        $subject->verify($token, ['undefined_custom_constraint' => 'anything']);
    }

    protected function newSubject(): OIDCTokenVerifier
    {
        return new OIDCTokenVerifier(
            new ArrayCertificateProvider($this->certs),
            $this->expected_issuer
        );
    }

    /**
     * @param string $issuer
     * @param array  $cert_ids
     */
    protected function givenCertProviderWithCerts(string $issuer, array $cert_ids): void
    {
        $this->certs = [];
        foreach ($cert_ids as $key) {
            $this->certs[$issuer][static::$keys[$key]['kid']] = static::$keys[$key]['public'];
        }
    }

    /**
     * @param array $payload
     * @param       $use_kid
     *
     * @return string
     */
    protected function createJwtWithKey(array $payload, $use_kid): string
    {
        $payload = array_merge(
            [
                'aud'            => 'https://foo.bar.com/anything',
                'azp'            => 'any-authorized-party-value',
                'email'          => 'my-email-account@wherever.com',
                'email_verified' => 1,
                'exp'            => time() + 3600,
                'iat'            => time(),
                'iss'            => 'https://some.account.provider',
                'sub'            => 'any-user-id'
            ],
            $payload
        );

        return JWT::encode(
            $payload,
            static::$keys[$use_kid]['private'],
            'RS256',
            static::$keys[$use_kid]['kid']
        );
    }

    /**
     * @param \Ingenerator\OIDCTokenVerifier\OIDCTokenVerifier $subject
     * @param string                                           $token
     *
     * @return \Ingenerator\OIDCTokenVerifier\TokenVerificationResult
     */
    protected function assertFailsVerification(
        OIDCTokenVerifier $subject,
        string $token
    ): TokenVerificationResult {

    }

    /**
     * @param array $payload
     *
     * @return string
     */
    protected function givenTokenThatWillPassBasicVerification(array $payload): string
    {
        $token = $this->createJwtWithKey(
            \array_merge($payload, ['iss' => 'https://account.prov']),
            'e762'
        );
        $this->givenCertProviderWithCerts('https://account.prov', ['e762']);
        $this->expected_issuer = 'https://account.prov';

        return $token;
    }
}
