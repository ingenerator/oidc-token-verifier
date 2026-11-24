<?php

declare(strict_types=1);

namespace test\unit\Ingenerator\OIDCTokenVerifier;

use DateInterval;
use DateTimeImmutable;
use DateTimeInterface;
use Firebase\JWT\Key;
use GuzzleHttp\Psr7\Response;
use Ingenerator\OIDCTokenVerifier\CertificateDiscoveryFailedException;
use Ingenerator\OIDCTokenVerifier\OpenIDDiscoveryCertificateProvider;
use InvalidArgumentException;
use Iterator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Psr\Log\Test\TestLogger;
use test\mock\Ingenerator\OIDCTokenVerifier\Cache\MockCacheItemPool;
use test\mock\Ingenerator\OIDCTokenVerifier\GuzzleClientMocker;

use function array_map;
use function json_encode;
use function openssl_pkey_get_details;

final class OpenIDDiscoveryCertificateProviderTest extends TestCase
{
    public const string CERT_PEM_7F725 = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqOpAAmY20iOCNu8c913Y\noMv01U817A/SrTsN6Ocgejp2CoBs9OeibGCzH6TibjxGbHPlC6LOk4dHDrqGkbhX\naWPaISVlaqplzRAxpeEAkJhfuzFqqDtyN3wJPfj0skDn3TeTqmEydwLbexlwLMh8\nPzsj+YwDQsEvono2y9Yq5jb3qNe2SsJUMpAm2lcM49EHdbvcwLx6taVBcs/UVbqu\nrGvYp4AbfzNLlDoGe3lZBZ55OjDRcfxsOJsw+dCx4mTr+UGJe50LFUfG/bkZ18TT\nbGxHiJmqYUrnmM9LVyihM3rd/aQa5I/zBtwbMo6/ntDhiF4klYr/xgXhvGlxog0d\nEwIDAQAB\n-----END PUBLIC KEY-----\n";
    public const string CERT_PEM_C952C = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmvj+0waJ2owQlFWrlC06\ngoLs9PcNehIzCF0QrkdsYZJXOsipcHCFlXBsgQIdTdLvlCzNI07jSYA+zggycYi9\n6lfDX+FYv/CqC8dRLf9TBOPvUgCyFMCFNUTC69hsrEYMR/J79Wj0MIOffiVr6eX+\nAaCG3KhBMZMh15KCdn3uVrl9coQivy7bk2Uw+aUJ/b26C0gWYj1DnpO4UEEKBk1X\n+lpeUMh0B/XorqWeq0NYK2pN6CoEIh0UrzYKlGfdnMU1pJJCsNxMiha+Vw3qqxez\n6oytOV/AswlWvQc7TkSX6cHfqepNskQb7pGxpgQpy9sA34oIxB/S+O7VS7/h0Qh4\nvQIDAQAB\n-----END PUBLIC KEY-----\n";

    private MockCacheItemPool $cache;

    private GuzzleClientMocker $guzzle_mocker;

    private $options = [];

    private NullLogger|TestLogger|MockObject $log;

    public function testItIsInitialisable(): void
    {
        $this->assertInstanceOf(OpenIDDiscoveryCertificateProvider::class, $this->newSubject());
    }

    public function testItThrowsIfIssuerNotAUrl(): void
    {
        $subject = $this->newSubject();
        $this->expectException(InvalidArgumentException::class);
        $subject->getCertificates('i.am.never.valid');
    }

    #[TestWith(['http://foo.bar', [], true])]
    #[TestWith(['http://foo.bar', ['allow_insecure' => true], false])]
    #[TestWith(['http://foo.bar', ['allow_insecure' => false], true])]
    #[TestWith(['https://foo.bar', ['allow_insecure' => true], false])]
    #[TestWith(['https://foo.bar', ['allow_insecure' => false], false])]
    public function testItThrowsIfIssuerNotHttpsUnlessAllowInsecure($iss, $options, $expect_exception): void
    {
        $this->options = $options;
        if (!$expect_exception) {
            $this->guzzle_mocker = GuzzleClientMocker::withResponses(
                self::makeDiscoveryDocResponse(),
                self::makeDefaultJWKSResponse()
            );
        }

        $subject = $this->newSubject();

        if ($expect_exception) {
            $this->expectException(InvalidArgumentException::class);
            $this->expectExceptionMessage('Cannot auto-discover certificates');
        }

        $subject->getCertificates($iss);
    }

    public static function provider_jwks_fetch_errors(): Iterator
    {
        $iss = 'https://borked-cert-provider.com';
        yield 'Discovery URL is 500' => [
            new Response(500, [], 'Argh'),
        ];
        yield 'Discovery doc not JSON' => [
            new Response(200, [], 'I am a teapot'),
        ];
        yield 'Discovery doc has no jwks_uri' => [
            new Response(200, [], json_encode(['anything'])),
        ];
        yield 'jwks doc is 404' => [
            self::makeDiscoveryDocResponse('https://anywhere/jwks.json', $iss),
            new Response(404, [], 'I no here'),
        ];
        yield 'jwks doc is not schema-valid' => [
            self::makeDiscoveryDocResponse('https://anywhere/jwks.json', $iss),
            new Response(200, [], json_encode(['this' => 'is junk'])),
        ];
        yield 'jwks doc has broken key data' => [
            self::makeDiscoveryDocResponse('https://anywhere/jwks.json', $iss),
            self::makeJWKSResponseWithKeys(
                [
                    [
                        'e' => 'AQAB',
                        'n' => 'anything',
                        'kid' => 'd12e77e0024a861a60fa4df2efa1b9348e0c1540',
                        'use' => 'sig',
                        'alg' => 'RSA256',
                        // 'kty' => 'RSA',
                    ],
                ]
            ),
        ];
        yield 'jwks doc has invalid expires header' => [
            self::makeDiscoveryDocResponse(),
            self::makeDefaultJWKSResponse()->withHeader('Expires', 'No'),
        ];
    }

    #[DataProvider('provider_jwks_fetch_errors')]
    public function testItThrowsOnErrorFetchingJwksIfNoCachedValues(
        Response ...$responses,
    ): void {
        $this->guzzle_mocker = GuzzleClientMocker::withResponses(...$responses);
        $subj = $this->newSubject();
        $this->expectException(CertificateDiscoveryFailedException::class);
        $subj->getCertificates('https://anyone.com');
    }

    public function testIfCacheEmptyItFetchesDiscoveryDocumentToLocateJwksUri(): void
    {
        $this->guzzle_mocker = GuzzleClientMocker::withResponses(
            self::makeDiscoveryDocResponse('https://foo.bar.com/oauth2/v3/certs'),
            self::makeDefaultJWKSResponse()
        );

        $this->newSubject()->getCertificates('https://accounts.bar.com');

        $this->guzzle_mocker->assertExactRequestSequence(
            [
                'GET https://accounts.bar.com/.well-known/openid-configuration',
                'GET https://foo.bar.com/oauth2/v3/certs',
            ]
        );
    }

    public function testItReturnsKeysParsedFromJwksDocumentIfCacheEmpty(): void
    {
        $this->guzzle_mocker = GuzzleClientMocker::withResponses(
            self::makeDiscoveryDocResponse(),
            self::makeDefaultJWKSResponse()
        );

        $certs = $this->newSubject()->getCertificates('https://accounts.anyone.com');

        $this->assertSameOpenSSLPublicKeys(
            [
                '4b83f18023a855587f942e75102251120887f725' => self::CERT_PEM_7F725,
                '2c6fa6f5950a7ce465fcf247aa0b094828ac952c' => self::CERT_PEM_C952C,
            ],
            $certs
        );
    }

    #[TestWith(['https://accounts.anyone.com', [], 'openid_jwks|e6f867764d04c07b7fda10fd4ae7e57be5c289f5'])]
    #[TestWith([
        'https://accounts.anyone.com',
        ['cache_key_prefix' => 'custom'],
        'custom|e6f867764d04c07b7fda10fd4ae7e57be5c289f5',
    ])]
    #[TestWith(['https://my.account.srv', [], 'openid_jwks|01ab28ccb6eeb5269a46ffe723c1a4b5f8bab8c1'])]
    public function testItSetsCacheKeysBasedOnPrefixAndShaOfIssuer($iss, $opts, $expect): void
    {
        $this->guzzle_mocker = GuzzleClientMocker::withResponses(
            self::makeDiscoveryDocResponse(),
            self::makeDefaultJWKSResponse()
        );

        $this->options = array_merge($this->options, $opts);

        $this->newSubject()->getCertificates($iss);
        $this->assertSame([$expect], $this->cache->listSavedKeys());
    }

    #[TestWith([[], 'tomorrow 02:00:00'])]
    #[TestWith([['cache_refresh_grace_period' => 'PT4H'], 'tomorrow 04:00:00'])]
    public function testItCachesKeysWithHardTtlGracePeriodAfterExpiresTime(
        $opts,
        $expect,
    ): void {
        $this->guzzle_mocker = GuzzleClientMocker::withResponses(
            self::makeDiscoveryDocResponse(),
            self::makeDefaultJWKSResponse(new DateTimeImmutable('tomorrow 00:00:00'))
        );

        $this->options = \array_merge($this->options, $opts);
        $this->newSubject()->getCertificates('https://accounts.anyone.com');

        $cache_item = $this->cache->getOnlyItem();

        $this->assertEquals(new DateTimeImmutable($expect), $cache_item->getExpiresAt());
    }

    public function testItCachesForGracePeriodIfNoExpiresHeader(): void
    {
        $one_hour_thirty = new DateInterval('PT1H30M');
        $time_start = new DateTimeImmutable();
        $this->options['cache_refresh_grace_period'] = 'PT1H';
        $this->options['cache_expires_if_no_header'] = 'PT30M';

        $this->guzzle_mocker = GuzzleClientMocker::withResponses(
            self::makeDiscoveryDocResponse(),
            self::makeDefaultJWKSResponse(null)
        );

        $this->newSubject()->getCertificates('https://accounts.anyone.com');

        $cache_item = $this->cache->getOnlyItem();

        // Expiry time should be more than 1h30 after the start of the test, but less than 1h30 from
        // now.
        $cache_expires = $cache_item->getExpiresAt();
        $this->assertGreaterThan($time_start->add($one_hour_thirty), $cache_expires);
        $this->assertLessThan(new DateTimeImmutable()->add($one_hour_thirty), $cache_expires);
    }

    public function testIfCachePresentItReturnsCachedValueWithoutHttpRequests(): void
    {
        $this->givenPreviouslyRequestedAndCachedJWKs('https://accounts.anyone.com');

        $this->guzzle_mocker = GuzzleClientMocker::withNoResponses();
        $certs = $this->newSubject()->getCertificates('https://accounts.anyone.com');
        $this->assertSameOpenSSLPublicKeys(
            [
                '4b83f18023a855587f942e75102251120887f725' => self::CERT_PEM_7F725,
                '2c6fa6f5950a7ce465fcf247aa0b094828ac952c' => self::CERT_PEM_C952C,
            ],
            $certs
        );
        $this->guzzle_mocker->assertNoRequestsSent();
    }

    public function testIfCacheSoftExpiredItFetchesAndCachesNewValues(): void
    {
        $this->givenPreviouslyRequestedAndCachedJWKs(
            'https://accounts.anyone.com',
            new DateTimeImmutable('-5 minutes')
        );

        $this->guzzle_mocker = GuzzleClientMocker::withResponses(
            self::makeDiscoveryDocResponse(
                'https://foo.bar.com/oauth2/v3/certs',
                'https://accounts.bar.com'
            ),
            $this->makeJWKSResponseWithKeys(
                [
                    [
                        'e' => 'AQAB',
                        'n' => 'r-rlzRqEj4tjNOhEBW5XVafi-0S2CzHyEHM09sy6tN_c_wrrbGj6tTawzRdPpI4z6pRgND2Zb_mKV9RBQjLk1xWijCN4ifOZmKUAx0rnmuv2Fc5-3Re-bvnJQE79aO9mMVS4wi-RVYbUPtU6fajxKeOLIyzEChtwTLKR0uLotHF7JQkP_3HVBXwF0h5iElXU9ycSUTQMzcpBgT52tUlEJA-d5-KhXTFIg2iHnSkiT-SWwbDJW5s0iVO8gNkpFwixKqsKjuJUcx4ysBTGlwsSMBWlyuJpywIQozaqNb-u1ijh7vOo3tRo3iR1Mu1RDa4ssyXaZc4plQ67UiBNKzhv0w',
                        'kid' => 'd12e77e0024a861a60fa4df2efa1b9348e0c1540',
                        'use' => 'sig',
                        'alg' => 'RSA256',
                        'kty' => 'RSA',
                    ],
                    [
                        'e' => 'AQAB',
                        'n' => 'rh8zYWxsJHX265kzfaWsgCBHMcNvMn4PE6xgdAgyZyQFzuJ1NqIZ3a0fItMQRHM2QzlW0VCWv4X7CObfnRJvoHUHYQMRoUGGZytZjsRw4JjLd2mI4i7KY3VVeqOi65DGWqiZiSwUsh5404JxNu-7n20FBLXr3eaT56F3Mn5mLBB-o5f5_olciMXkmwTt2ef3vGhhh9E7socYOmvqQGZm6-Tl0epLvLurqkNrzd9TYyOcVrl4mmsRNmi7bvKXGpfXySNWOtDxFu07UVtwf1A_0o1wqGDmKMju7JkL598syeLgMWiwNW2rqBccjWI8FRJsVpsc3fVnuXL70bTu1A2IIw',
                        'kid' => '1c93fa48c428560264ef0d79fc6bbd098b91fe0a',
                        'use' => 'sig',
                        'alg' => 'RSA256',
                        'kty' => 'RSA',
                    ],
                ]
            )
        );

        $certs = $this->newSubject()->getCertificates('https://accounts.anyone.com');
        $this->assertSameOpenSSLPublicKeys(
            [
                'd12e77e0024a861a60fa4df2efa1b9348e0c1540' => "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr+rlzRqEj4tjNOhEBW5X\nVafi+0S2CzHyEHM09sy6tN/c/wrrbGj6tTawzRdPpI4z6pRgND2Zb/mKV9RBQjLk\n1xWijCN4ifOZmKUAx0rnmuv2Fc5+3Re+bvnJQE79aO9mMVS4wi+RVYbUPtU6fajx\nKeOLIyzEChtwTLKR0uLotHF7JQkP/3HVBXwF0h5iElXU9ycSUTQMzcpBgT52tUlE\nJA+d5+KhXTFIg2iHnSkiT+SWwbDJW5s0iVO8gNkpFwixKqsKjuJUcx4ysBTGlwsS\nMBWlyuJpywIQozaqNb+u1ijh7vOo3tRo3iR1Mu1RDa4ssyXaZc4plQ67UiBNKzhv\n0wIDAQAB\n-----END PUBLIC KEY-----\n",
                '1c93fa48c428560264ef0d79fc6bbd098b91fe0a' => "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArh8zYWxsJHX265kzfaWs\ngCBHMcNvMn4PE6xgdAgyZyQFzuJ1NqIZ3a0fItMQRHM2QzlW0VCWv4X7CObfnRJv\noHUHYQMRoUGGZytZjsRw4JjLd2mI4i7KY3VVeqOi65DGWqiZiSwUsh5404JxNu+7\nn20FBLXr3eaT56F3Mn5mLBB+o5f5/olciMXkmwTt2ef3vGhhh9E7socYOmvqQGZm\n6+Tl0epLvLurqkNrzd9TYyOcVrl4mmsRNmi7bvKXGpfXySNWOtDxFu07UVtwf1A/\n0o1wqGDmKMju7JkL598syeLgMWiwNW2rqBccjWI8FRJsVpsc3fVnuXL70bTu1A2I\nIwIDAQAB\n-----END PUBLIC KEY-----\n",
            ],
            $certs
        );
    }

    public function testIfCacheSoftExpiredItReturnsPreviousCachedValuesOnRefreshError(): void
    {
        $this->log = new NullLogger();
        $this->givenPreviouslyRequestedAndCachedJWKs(
            'https://accounts.anyone.com',
            new DateTimeImmutable('-5 minutes')
        );

        $this->guzzle_mocker = GuzzleClientMocker::withResponses(
            new Response(500, [], 'Broken')
        );

        $certs = $this->newSubject()->getCertificates('https://accounts.anyone.com');

        $this->assertSameOpenSSLPublicKeys(
            [
                '4b83f18023a855587f942e75102251120887f725' => self::CERT_PEM_7F725,
                '2c6fa6f5950a7ce465fcf247aa0b094828ac952c' => self::CERT_PEM_C952C,
            ],
            $certs
        );
    }

    public function testItLogsErrorsRefreshingCertificatesDuringGracePeriod(): void
    {
        $this->log = new TestLogger();
        $this->givenPreviouslyRequestedAndCachedJWKs(
            'https://accounts.anyone.com',
            new DateTimeImmutable('-5 minutes')
        );

        $this->guzzle_mocker = GuzzleClientMocker::withResponses(
            new Response(500, [], 'Broken')
        );

        $this->newSubject()->getCertificates('https://accounts.anyone.com');

        $this->assertTrue($this->log->hasWarningThatMatches('/500/'));
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->cache = MockCacheItemPool::empty();
        $this->guzzle_mocker = GuzzleClientMocker::withNoResponses();
        $this->log = $this->createMock(LoggerInterface::class);
        $this->log->expects($this->never())->method($this->anything());
    }

    protected function newSubject(): OpenIDDiscoveryCertificateProvider
    {
        return new OpenIDDiscoveryCertificateProvider(
            $this->guzzle_mocker->getClient(),
            $this->cache,
            $this->log,
            $this->options
        );
    }

    protected static function makeDiscoveryDocument(string $jwks_uri, string $issuer): array
    {
        $discovery = [
            'issuer' => $issuer,
            'authorization_endpoint' => 'https://accounts.foo.com/o/oauth2/v2/auth',
            'device_authorization_endpoint' => 'https://oauth2.whatever.com/device/code',
            'token_endpoint' => 'https://oauth2.whatever.com/token',
            'userinfo_endpoint' => 'https://openidconnect.whatever.com/v1/userinfo',
            'revocation_endpoint' => 'https://oauth2.whatever.com/revoke',
            'jwks_uri' => $jwks_uri,
            'response_types_supported' => [
                'code',
                'token',
                'id_token',
                'code token',
                'code id_token',
                'token id_token',
                'code token id_token',
                'none',
            ],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'scopes_supported' => ['openid', 'email', 'profile'],
            'token_endpoint_auth_methods_supported' => [
                'client_secret_post',
                'client_secret_basic',
            ],
            'claims_supported' => [
                'aud',
                'email',
                'email_verified',
                'exp',
                'family_name',
                'given_name',
                'iat',
                'iss',
                'locale',
                'name',
                'picture',
                'sub',
            ],
            'code_challenge_methods_supported' => ['plain', 'S256'],
            'grant_types_supported' => [
                'authorization_code',
                'refresh_token',
                'urn:ietf:params:oauth:grant-type:device_code',
                'urn:ietf:params:oauth:grant-type:jwt-bearer',
            ],
        ];

        return $discovery;
    }

    protected static function makeDefaultJWKSResponse(
        ?DateTimeImmutable $expires = new DateTimeImmutable('+20 minutes'),
    ): Response {
        return self::makeJWKSResponseWithKeys(
            [
                [
                    'e' => 'AQAB',
                    'n' => 'qOpAAmY20iOCNu8c913YoMv01U817A_SrTsN6Ocgejp2CoBs9OeibGCzH6TibjxGbHPlC6LOk4dHDrqGkbhXaWPaISVlaqplzRAxpeEAkJhfuzFqqDtyN3wJPfj0skDn3TeTqmEydwLbexlwLMh8Pzsj-YwDQsEvono2y9Yq5jb3qNe2SsJUMpAm2lcM49EHdbvcwLx6taVBcs_UVbqurGvYp4AbfzNLlDoGe3lZBZ55OjDRcfxsOJsw-dCx4mTr-UGJe50LFUfG_bkZ18TTbGxHiJmqYUrnmM9LVyihM3rd_aQa5I_zBtwbMo6_ntDhiF4klYr_xgXhvGlxog0dEw',
                    'kid' => '4b83f18023a855587f942e75102251120887f725',
                    'use' => 'sig',
                    'alg' => 'RS256',
                    'kty' => 'RSA',
                ],
                [
                    'kty' => 'RSA',
                    'n' => 'mvj-0waJ2owQlFWrlC06goLs9PcNehIzCF0QrkdsYZJXOsipcHCFlXBsgQIdTdLvlCzNI07jSYA-zggycYi96lfDX-FYv_CqC8dRLf9TBOPvUgCyFMCFNUTC69hsrEYMR_J79Wj0MIOffiVr6eX-AaCG3KhBMZMh15KCdn3uVrl9coQivy7bk2Uw-aUJ_b26C0gWYj1DnpO4UEEKBk1X-lpeUMh0B_XorqWeq0NYK2pN6CoEIh0UrzYKlGfdnMU1pJJCsNxMiha-Vw3qqxez6oytOV_AswlWvQc7TkSX6cHfqepNskQb7pGxpgQpy9sA34oIxB_S-O7VS7_h0Qh4vQ',
                    'e' => 'AQAB',
                    'kid' => '2c6fa6f5950a7ce465fcf247aa0b094828ac952c',
                    'alg' => 'RS256',
                    'use' => 'sig',
                ],
            ],
            $expires
        );
    }

    protected static function makeDiscoveryDocResponse(
        string $jwks_uri = 'https://foo.anyone.com/oauth2/v3/certs',
        string $issuer = 'https://accounts.anyone.com',
    ): Response {
        $discovery = self::makeDiscoveryDocument($jwks_uri, $issuer);

        return new Response(
            200,
            ['Content-Type' => 'application/json; charset=UTF-8'],
            json_encode($discovery)
        );
    }

    protected function givenPreviouslyRequestedAndCachedJWKs(
        string $issuer,
        DateTimeImmutable $expires = new DateTimeImmutable('+20 minutes'),
    ): void {
        $this->guzzle_mocker = GuzzleClientMocker::withResponses(
            self::makeDiscoveryDocResponse(),
            self::makeDefaultJWKSResponse($expires)
        );

        $this->newSubject()->getCertificates($issuer);
    }

    protected static function makeJWKSResponseWithKeys(
        array $keys,
        ?DateTimeImmutable $expires = new DateTimeImmutable('+20 minutes'),
    ): Response {
        $headers = [
            'Content-Type' => 'application/json; charset=UTF-8',
        ];
        if ($expires instanceof DateTimeImmutable) {
            $headers['Expires'] = $expires->format(DateTimeInterface::RFC1123);
        }

        return new Response(
            200,
            $headers,
            json_encode(['keys' => $keys])
        );
    }

    /**
     * @param array<string, string> $expected_certs
     * @param Key[] $actual_certs
     */
    private function assertSameOpenSSLPublicKeys(array $expected_certs, array $actual_certs): void
    {
        $this->assertSame(
            $expected_certs,
            array_map(
                fn (Key $key) => openssl_pkey_get_details($key->getKeyMaterial())['key'],
                $actual_certs
            )
        );
    }
}
