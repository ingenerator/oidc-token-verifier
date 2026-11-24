<?php

declare(strict_types=1);

namespace test\unit\Ingenerator\OIDCTokenVerifier;

use Ingenerator\OIDCTokenVerifier\ArrayCertificateProvider;
use Ingenerator\OIDCTokenVerifier\CertificateDiscoveryFailedException;
use Ingenerator\OIDCTokenVerifier\CertificateProvider;
use PHPUnit\Framework\TestCase;

/**
 * @phpstan-import-type TCertificateKeyMap from CertificateProvider
 */
final class ArrayCertificateProviderTest extends TestCase
{
    /**
     * @var array<string, TCertificateKeyMap>
     */
    private array $issuer_certs = [];

    public function testItIsInitialisable(): void
    {
        $this->assertInstanceOf(ArrayCertificateProvider::class, $this->newSubject());
    }

    public function testItThrowsCertificateDiscoveryFailedIfNoCertsForIssuer(): void
    {
        $this->issuer_certs = [
            'https://some.one' => [
                '4b83f18023a855587f942e75102251120887f725' => "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqOpAAmY20iOCNu8c913Y\noMv01U817A/SrTsN6Ocgejp2CoBs9OeibGCzH6TibjxGbHPlC6LOk4dHDrqGkbhX\naWPaISVlaqplzRAxpeEAkJhfuzFqqDtyN3wJPfj0skDn3TeTqmEydwLbexlwLMh8\nPzsj+YwDQsEvono2y9Yq5jb3qNe2SsJUMpAm2lcM49EHdbvcwLx6taVBcs/UVbqu\nrGvYp4AbfzNLlDoGe3lZBZ55OjDRcfxsOJsw+dCx4mTr+UGJe50LFUfG/bkZ18TT\nbGxHiJmqYUrnmM9LVyihM3rd/aQa5I/zBtwbMo6/ntDhiF4klYr/xgXhvGlxog0d\nEwIDAQAB\n-----END PUBLIC KEY-----\n",
                '2c6fa6f5950a7ce465fcf247aa0b094828ac952c' => "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmvj+0waJ2owQlFWrlC06\ngoLs9PcNehIzCF0QrkdsYZJXOsipcHCFlXBsgQIdTdLvlCzNI07jSYA+zggycYi9\n6lfDX+FYv/CqC8dRLf9TBOPvUgCyFMCFNUTC69hsrEYMR/J79Wj0MIOffiVr6eX+\nAaCG3KhBMZMh15KCdn3uVrl9coQivy7bk2Uw+aUJ/b26C0gWYj1DnpO4UEEKBk1X\n+lpeUMh0B/XorqWeq0NYK2pN6CoEIh0UrzYKlGfdnMU1pJJCsNxMiha+Vw3qqxez\n6oytOV/AswlWvQc7TkSX6cHfqepNskQb7pGxpgQpy9sA34oIxB/S+O7VS7/h0Qh4\nvQIDAQAB\n-----END PUBLIC KEY-----\n",
            ],
        ];
        $subject = $this->newSubject();
        $this->expectException(CertificateDiscoveryFailedException::class);
        $subject->getCertificates('https://other.issuer');
    }

    public function testItReturnsIssuerCertsIfConfigured(): void
    {
        $certs = [
            '4b83f18023a855587f942e75102251120887f725' => "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqOpAAmY20iOCNu8c913Y\noMv01U817A/SrTsN6Ocgejp2CoBs9OeibGCzH6TibjxGbHPlC6LOk4dHDrqGkbhX\naWPaISVlaqplzRAxpeEAkJhfuzFqqDtyN3wJPfj0skDn3TeTqmEydwLbexlwLMh8\nPzsj+YwDQsEvono2y9Yq5jb3qNe2SsJUMpAm2lcM49EHdbvcwLx6taVBcs/UVbqu\nrGvYp4AbfzNLlDoGe3lZBZ55OjDRcfxsOJsw+dCx4mTr+UGJe50LFUfG/bkZ18TT\nbGxHiJmqYUrnmM9LVyihM3rd/aQa5I/zBtwbMo6/ntDhiF4klYr/xgXhvGlxog0d\nEwIDAQAB\n-----END PUBLIC KEY-----\n",
            '2c6fa6f5950a7ce465fcf247aa0b094828ac952c' => "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmvj+0waJ2owQlFWrlC06\ngoLs9PcNehIzCF0QrkdsYZJXOsipcHCFlXBsgQIdTdLvlCzNI07jSYA+zggycYi9\n6lfDX+FYv/CqC8dRLf9TBOPvUgCyFMCFNUTC69hsrEYMR/J79Wj0MIOffiVr6eX+\nAaCG3KhBMZMh15KCdn3uVrl9coQivy7bk2Uw+aUJ/b26C0gWYj1DnpO4UEEKBk1X\n+lpeUMh0B/XorqWeq0NYK2pN6CoEIh0UrzYKlGfdnMU1pJJCsNxMiha+Vw3qqxez\n6oytOV/AswlWvQc7TkSX6cHfqepNskQb7pGxpgQpy9sA34oIxB/S+O7VS7/h0Qh4\nvQIDAQAB\n-----END PUBLIC KEY-----\n",
        ];
        $this->issuer_certs = ['https://some.one' => $certs];
        $this->assertSame($certs, $this->newSubject()->getCertificates('https://some.one'));
    }

    protected function newSubject(): ArrayCertificateProvider
    {
        return new ArrayCertificateProvider($this->issuer_certs);
    }
}
