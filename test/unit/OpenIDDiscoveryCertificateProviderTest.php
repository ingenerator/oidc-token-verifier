<?php


namespace test\unit\Ingenerator\OIDCTokenVerifier;


use Firebase\JWT\Key;
use GuzzleHttp\Psr7\Response;
use Ingenerator\OIDCTokenVerifier\CertificateDiscoveryFailedException;
use Ingenerator\OIDCTokenVerifier\OpenIDDiscoveryCertificateProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Psr\Log\Test\TestLogger;
use test\mock\Ingenerator\OIDCTokenVerifier\Cache\MockCacheItemPool;
use test\mock\Ingenerator\OIDCTokenVerifier\GuzzleClientMocker;
use function array_map;
use function openssl_pkey_get_details;

class OpenIDDiscoveryCertificateProviderTest extends TestCase
{

    const CERT_PEM_7F725 = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqOpAAmY20iOCNu8c913Y\noMv01U817A/SrTsN6Ocgejp2CoBs9OeibGCzH6TibjxGbHPlC6LOk4dHDrqGkbhX\naWPaISVlaqplzRAxpeEAkJhfuzFqqDtyN3wJPfj0skDn3TeTqmEydwLbexlwLMh8\nPzsj+YwDQsEvono2y9Yq5jb3qNe2SsJUMpAm2lcM49EHdbvcwLx6taVBcs/UVbqu\nrGvYp4AbfzNLlDoGe3lZBZ55OjDRcfxsOJsw+dCx4mTr+UGJe50LFUfG/bkZ18TT\nbGxHiJmqYUrnmM9LVyihM3rd/aQa5I/zBtwbMo6/ntDhiF4klYr/xgXhvGlxog0d\nEwIDAQAB\n-----END PUBLIC KEY-----\n";
    const CERT_PEM_C952C = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmvj+0waJ2owQlFWrlC06\ngoLs9PcNehIzCF0QrkdsYZJXOsipcHCFlXBsgQIdTdLvlCzNI07jSYA+zggycYi9\n6lfDX+FYv/CqC8dRLf9TBOPvUgCyFMCFNUTC69hsrEYMR/J79Wj0MIOffiVr6eX+\nAaCG3KhBMZMh15KCdn3uVrl9coQivy7bk2Uw+aUJ/b26C0gWYj1DnpO4UEEKBk1X\n+lpeUMh0B/XorqWeq0NYK2pN6CoEIh0UrzYKlGfdnMU1pJJCsNxMiha+Vw3qqxez\n6oytOV/AswlWvQc7TkSX6cHfqepNskQb7pGxpgQpy9sA34oIxB/S+O7VS7/h0Qh4\nvQIDAQAB\n-----END PUBLIC KEY-----\n";

    /**
     * @var \test\mock\Ingenerator\OIDCTokenVerifier\Cache\MockCacheItemPool
     */
    protected $cache;

    /**
     * @var \test\mock\Ingenerator\OIDCTokenVerifier\GuzzleClientMocker
     */
    protected $guzzle_mocker;

    protected $options = [];

    protected $log;

    public function test_it_is_initialisable()
    {
        $this->assertInstanceOf(OpenIDDiscoveryCertificateProvider::class, $this->newSubject());
    }

    public function test_it_throws_if_issuer_not_a_url()
    {
        $subject = $this->newSubject();
        $this->expectException(\InvalidArgumentException::class);
        $subject->getCertificates('i.am.never.valid');
    }

    /**
     * @testWith ["http://foo.bar", {}, true]
     *           ["http://foo.bar", {"allow_insecure": true}, false]
     *           ["http://foo.bar", {"allow_insecure": false}, true]
     *           ["https://foo.bar", {"allow_insecure": true}, false]
     *           ["https://foo.bar", {"allow_insecure": false}, false]
     */
    public function test_it_throws_if_issuer_not_https_unless_allow_insecure($iss, $options, $expect_exception)
    {
        $this->options = $options;
        if ( ! $expect_exception) {
            $this->guzzle_mocker = GuzzleClientMocker::withResponses(
                $this->makeDiscoveryDocResponse(),
                $this->makeDefaultJWKSResponse()
            );
        }

        $subject = $this->newSubject();

        if ($expect_exception) {
            $this->expectException(\InvalidArgumentException::class);
            $this->expectExceptionMessage('Cannot auto-discover certificates');
        }

        $subject->getCertificates($iss);
    }

    public function provider_jwks_fetch_errors()
    {
        $iss = 'https://borked-cert-provider.com';

        return [
            [
                'Discovery URL is 500',
                new Response(500, [], 'Argh')
            ],
            [
                'Discovery doc not JSON',
                new Response(200, [], 'I am a teapot')
            ],
            [
                'Discovery doc has no jwks_uri',
                new Response(200, [], \GuzzleHttp\json_encode(['anything']))
            ],
            [
                'jwks doc is 404',
                $this->makeDiscoveryDocResponse('https://anywhere/jwks.json', $iss),
                new Response(404, [], 'I no here')
            ],
            [
                'jwks doc is not schema-valid',
                $this->makeDiscoveryDocResponse('https://anywhere/jwks.json', $iss),
                new Response(200, [], json_encode(['this' => 'is junk']))
            ],
            [
                'jwks doc has broken key data',
                $this->makeDiscoveryDocResponse('https://anywhere/jwks.json', $iss),
                $this->makeJWKSResponseWithKeys(
                    [
                        [
                            'e'   => 'AQAB',
                            'n'   => 'anything',
                            'kid' => 'd12e77e0024a861a60fa4df2efa1b9348e0c1540',
                            'use' => 'sig',
                            'alg' => 'RSA256',
                            // 'kty' => 'RSA',
                        ],
                    ]
                )
            ],
            [
                'jwks doc has invalid expires header',
                $this->makeDiscoveryDocResponse(),
                $this->makeDefaultJWKSResponse()->withHeader('Expires', 'No')
            ],
            [
                'jwks doc has no expires header',
                $this->makeDiscoveryDocResponse(),
                $this->makeDefaultJWKSResponse()->withoutHeader('Expires')
            ]
        ];
    }

    /**
     * @dataProvider provider_jwks_fetch_errors
     */
    public function test_it_throws_on_error_fetching_jwks_if_no_cached_values(
        string $case,
        Response...$responses
    ) {
        $this->guzzle_mocker = GuzzleClientMocker::withResponses(...$responses);
        $subj                = $this->newSubject();
        $this->expectException(CertificateDiscoveryFailedException::class);
        $subj->getCertificates('https://anyone.com');
    }

    public function test_if_cache_empty_it_fetches_discovery_document_to_locate_jwks_uri()
    {
        $this->guzzle_mocker = GuzzleClientMocker::withResponses(
            $this->makeDiscoveryDocResponse('https://foo.bar.com/oauth2/v3/certs'),
            $this->makeDefaultJWKSResponse()
        );

        $this->newSubject()->getCertificates('https://accounts.bar.com');

        $this->guzzle_mocker->assertExactRequestSequence(
            [
                'GET https://accounts.bar.com/.well-known/openid-configuration',
                'GET https://foo.bar.com/oauth2/v3/certs',
            ]
        );
    }

    public function test_it_returns_keys_parsed_from_jwks_document_if_cache_empty()
    {
        $this->guzzle_mocker = GuzzleClientMocker::withResponses(
            $this->makeDiscoveryDocResponse(),
            $this->makeDefaultJWKSResponse()
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

    /**
     * @testWith ["https://accounts.anyone.com", [], "openid_jwks|e6f867764d04c07b7fda10fd4ae7e57be5c289f5"]
     *           ["https://accounts.anyone.com", {"cache_key_prefix": "custom"}, "custom|e6f867764d04c07b7fda10fd4ae7e57be5c289f5"]
     *           ["https://my.account.srv", [], "openid_jwks|01ab28ccb6eeb5269a46ffe723c1a4b5f8bab8c1"]
     */
    public function test_it_sets_cache_keys_based_on_prefix_and_sha_of_issuer($iss, $opts, $expect)
    {
        $this->guzzle_mocker = GuzzleClientMocker::withResponses(
            $this->makeDiscoveryDocResponse(),
            $this->makeDefaultJWKSResponse()
        );

        $this->options = array_merge($this->options, $opts);

        $this->newSubject()->getCertificates($iss);
        $this->assertSame([$expect], $this->cache->listSavedKeys());
    }

    /**
     * @testWith [[], "tomorrow 02:00:00"]
     *           [{"cache_refresh_grace_period": "PT4H"}, "tomorrow 04:00:00"]
     */
    public function test_it_caches_keys_with_hard_ttl_grace_period_after_expires_time(
        $opts,
        $expect
    ) {
        $this->guzzle_mocker = GuzzleClientMocker::withResponses(
            $this->makeDiscoveryDocResponse(),
            $this->makeDefaultJWKSResponse(new \DateTimeImmutable('tomorrow 00:00:00'))
        );

        $this->options = \array_merge($this->options, $opts);
        $this->newSubject()->getCertificates('https://accounts.anyone.com');

        $cache_item = $this->cache->getOnlyItem();

        $this->assertEquals(new \DateTimeImmutable($expect), $cache_item->getExpiresAt());
    }

    public function test_if_cache_present_it_returns_cached_value_without_http_requests()
    {
        $this->givenPreviouslyRequestedAndCachedJWKs('https://accounts.anyone.com');

        $this->guzzle_mocker = GuzzleClientMocker::withNoResponses();
        $certs               = $this->newSubject()->getCertificates('https://accounts.anyone.com');
        $this->assertSameOpenSSLPublicKeys(
            [
                '4b83f18023a855587f942e75102251120887f725' => self::CERT_PEM_7F725,
                '2c6fa6f5950a7ce465fcf247aa0b094828ac952c' => self::CERT_PEM_C952C,
            ],
            $certs
        );
        $this->guzzle_mocker->assertNoRequestsSent();
    }

    public function test_if_cache_soft_expired_it_fetches_and_caches_new_values()
    {
        $this->givenPreviouslyRequestedAndCachedJWKs(
            'https://accounts.anyone.com',
            new \DateTimeImmutable('-5 minutes')
        );

        $this->guzzle_mocker = GuzzleClientMocker::withResponses(
            $this->makeDiscoveryDocResponse(
                'https://foo.bar.com/oauth2/v3/certs',
                'https://accounts.bar.com'
            ),
            $this->makeJWKSResponseWithKeys(
                [
                    [
                        'e'   => 'AQAB',
                        'n'   => 'r-rlzRqEj4tjNOhEBW5XVafi-0S2CzHyEHM09sy6tN_c_wrrbGj6tTawzRdPpI4z6pRgND2Zb_mKV9RBQjLk1xWijCN4ifOZmKUAx0rnmuv2Fc5-3Re-bvnJQE79aO9mMVS4wi-RVYbUPtU6fajxKeOLIyzEChtwTLKR0uLotHF7JQkP_3HVBXwF0h5iElXU9ycSUTQMzcpBgT52tUlEJA-d5-KhXTFIg2iHnSkiT-SWwbDJW5s0iVO8gNkpFwixKqsKjuJUcx4ysBTGlwsSMBWlyuJpywIQozaqNb-u1ijh7vOo3tRo3iR1Mu1RDa4ssyXaZc4plQ67UiBNKzhv0w',
                        'kid' => 'd12e77e0024a861a60fa4df2efa1b9348e0c1540',
                        'use' => 'sig',
                        'alg' => 'RSA256',
                        'kty' => 'RSA',
                    ],
                    [
                        'e'   => 'AQAB',
                        'n'   => 'rh8zYWxsJHX265kzfaWsgCBHMcNvMn4PE6xgdAgyZyQFzuJ1NqIZ3a0fItMQRHM2QzlW0VCWv4X7CObfnRJvoHUHYQMRoUGGZytZjsRw4JjLd2mI4i7KY3VVeqOi65DGWqiZiSwUsh5404JxNu-7n20FBLXr3eaT56F3Mn5mLBB-o5f5_olciMXkmwTt2ef3vGhhh9E7socYOmvqQGZm6-Tl0epLvLurqkNrzd9TYyOcVrl4mmsRNmi7bvKXGpfXySNWOtDxFu07UVtwf1A_0o1wqGDmKMju7JkL598syeLgMWiwNW2rqBccjWI8FRJsVpsc3fVnuXL70bTu1A2IIw',
                        'kid' => '1c93fa48c428560264ef0d79fc6bbd098b91fe0a',
                        'use' => 'sig',
                        'alg' => 'RSA256',
                        'kty' => 'RSA',
                    ]
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

    public function test_if_cache_soft_expired_it_returns_previous_cached_values_on_refresh_error()
    {
        $this->log = new NullLogger;
        $this->givenPreviouslyRequestedAndCachedJWKs(
            'https://accounts.anyone.com',
            new \DateTimeImmutable('-5 minutes')
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

    public function test_it_logs_errors_refreshing_certificates_during_grace_period()
    {
        $this->log = new TestLogger;
        $this->givenPreviouslyRequestedAndCachedJWKs(
            'https://accounts.anyone.com',
            new \DateTimeImmutable('-5 minutes')
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
        $this->cache         = MockCacheItemPool::empty();
        $this->guzzle_mocker = GuzzleClientMocker::withNoResponses();
        $this->log           = $this->getMockBuilder(LoggerInterface::class)->getMock();
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

    /**
     * @param string $jwks_uri
     * @param string $issuer
     *
     * @return array
     */
    protected function makeDiscoveryDocument(string $jwks_uri, string $issuer): array
    {
        $discovery = [
            'issuer'                                => $issuer,
            'authorization_endpoint'                => 'https://accounts.foo.com/o/oauth2/v2/auth',
            'device_authorization_endpoint'         => 'https://oauth2.whatever.com/device/code',
            'token_endpoint'                        => 'https://oauth2.whatever.com/token',
            'userinfo_endpoint'                     => 'https://openidconnect.whatever.com/v1/userinfo',
            'revocation_endpoint'                   => 'https://oauth2.whatever.com/revoke',
            'jwks_uri'                              => $jwks_uri,
            'response_types_supported'              =>
                [
                    'code',
                    'token',
                    'id_token',
                    'code token',
                    'code id_token',
                    'token id_token',
                    'code token id_token',
                    'none',
                ],
            'subject_types_supported'               => ['public',],
            'id_token_signing_alg_values_supported' => ['RS256',],
            'scopes_supported'                      => ['openid', 'email', 'profile',],
            'token_endpoint_auth_methods_supported' => [
                'client_secret_post',
                'client_secret_basic',
            ],
            'claims_supported'                      =>
                [
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
            'code_challenge_methods_supported'      => ['plain', 'S256',],
            'grant_types_supported'                 => [
                'authorization_code',
                'refresh_token',
                'urn:ietf:params:oauth:grant-type:device_code',
                'urn:ietf:params:oauth:grant-type:jwt-bearer'
            ],
        ];

        return $discovery;
    }

    /**
     * @return \GuzzleHttp\Psr7\Response
     */
    protected function makeDefaultJWKSResponse(?\DateTimeImmutable $expires = NULL): Response
    {
        return $this->makeJWKSResponseWithKeys(
            [
                [
                    'e'   => 'AQAB',
                    'n'   => 'qOpAAmY20iOCNu8c913YoMv01U817A_SrTsN6Ocgejp2CoBs9OeibGCzH6TibjxGbHPlC6LOk4dHDrqGkbhXaWPaISVlaqplzRAxpeEAkJhfuzFqqDtyN3wJPfj0skDn3TeTqmEydwLbexlwLMh8Pzsj-YwDQsEvono2y9Yq5jb3qNe2SsJUMpAm2lcM49EHdbvcwLx6taVBcs_UVbqurGvYp4AbfzNLlDoGe3lZBZ55OjDRcfxsOJsw-dCx4mTr-UGJe50LFUfG_bkZ18TTbGxHiJmqYUrnmM9LVyihM3rd_aQa5I_zBtwbMo6_ntDhiF4klYr_xgXhvGlxog0dEw',
                    'kid' => '4b83f18023a855587f942e75102251120887f725',
                    'use' => 'sig',
                    'alg' => 'RS256',
                    'kty' => 'RSA'
                ],
                [
                    'kty' => 'RSA',
                    'n'   => 'mvj-0waJ2owQlFWrlC06goLs9PcNehIzCF0QrkdsYZJXOsipcHCFlXBsgQIdTdLvlCzNI07jSYA-zggycYi96lfDX-FYv_CqC8dRLf9TBOPvUgCyFMCFNUTC69hsrEYMR_J79Wj0MIOffiVr6eX-AaCG3KhBMZMh15KCdn3uVrl9coQivy7bk2Uw-aUJ_b26C0gWYj1DnpO4UEEKBk1X-lpeUMh0B_XorqWeq0NYK2pN6CoEIh0UrzYKlGfdnMU1pJJCsNxMiha-Vw3qqxez6oytOV_AswlWvQc7TkSX6cHfqepNskQb7pGxpgQpy9sA34oIxB_S-O7VS7_h0Qh4vQ',
                    'e'   => 'AQAB',
                    'kid' => '2c6fa6f5950a7ce465fcf247aa0b094828ac952c',
                    'alg' => 'RS256',
                    'use' => 'sig'
                ]
            ],
            $expires
        );
    }


    /**
     * @param string $jwks_uri
     * @param string $issuer
     *
     * @return \GuzzleHttp\Psr7\Response
     */
    protected function makeDiscoveryDocResponse(
        string $jwks_uri = 'https://foo.anyone.com/oauth2/v3/certs',
        string $issuer = 'https://accounts.anyone.com'
    ): Response {
        $discovery = $this->makeDiscoveryDocument($jwks_uri, $issuer);

        return new Response(
            200,
            ['Content-Type' => 'application/json; charset=UTF-8'],
            \json_encode($discovery)
        );
    }

    /**
     * @param string $issuer
     */
    protected function givenPreviouslyRequestedAndCachedJWKs(
        string $issuer,
        \DateTimeImmutable $expires = NULL
    ): void {
        $this->guzzle_mocker = GuzzleClientMocker::withResponses(
            $this->makeDiscoveryDocResponse(),
            $this->makeDefaultJWKSResponse($expires)
        );

        $this->newSubject()->getCertificates($issuer);
    }

    /**
     * @param array                   $keys
     * @param \DateTimeImmutable|null $expires
     *
     * @return \GuzzleHttp\Psr7\Response
     */
    protected function makeJWKSResponseWithKeys(
        array $keys,
        ?\DateTimeImmutable $expires = NULL
    ): Response {
        $expires = $expires ?? new \DateTimeImmutable('+20 minutes');

        return new Response(
            200,
            [
                'Content-Type' => 'application/json; charset=UTF-8',
                'Expires'      => $expires->format(\DateTimeInterface::RFC1123)
            ],
            \json_encode(['keys' => $keys])
        );
    }

    private function assertSameOpenSSLPublicKeys(array $expected_certs, array $actual_certs): void
    {
        $this->assertSame($expected_certs,
                          array_map(
                              fn(Key $key) => openssl_pkey_get_details($key->getKeyMaterial())['key'],
                              $actual_certs
                          )
        );
    }

}
