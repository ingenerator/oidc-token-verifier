<?php

namespace Ingenerator\OIDCTokenVerifier;

use DateInterval;
use DateTimeImmutable;
use DateTimeInterface;
use Exception;
use Firebase\JWT\JWK;
use Firebase\JWT\Key;
use GuzzleHttp\ClientInterface;
use InvalidArgumentException;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Log\LoggerInterface;

use function preg_match;
use function sprintf;

/**
 * Provides the certificates required to validate OpenID Connect tokens by fetching the discovery /
 * jwk document for the issuer.
 *
 * @phpstan-type TProviderOptions array{
 *   allow_insecure?: bool,
 *   cache_key_prefix?: string,
 *   cache_refresh_grace_period?: string,
 *   cache_expires_if_no_header?: string
 * }
 */
class OpenIDDiscoveryCertificateProvider implements CertificateProvider
{
    /**
     * @var array{
     *     allow_insecure: bool,
     *     cache_key_prefix: string,
     *     cache_refresh_grace_period: string,
     *     cache_expires_if_no_header: string
     * }
     */
    private array $options;

    /**
     * Options:
     *
     *   * allow_insecure - whether to fetch certs from an http URL (e.g. in development environments)
     *   * cache_key_prefix - the prefix to apply to cache keys to keep them separate from other code
     *   * cache_refresh_grace_period - how long to ignore errors and return a stale value if the certs cant be refreshed
     *   * cache_expires_if_no_header - how long to cache certificates if the provider does not provide an Expires header
     *
     * @param TProviderOptions $options
     */
    public function __construct(
        private readonly ClientInterface $guzzle,
        private readonly CacheItemPoolInterface $cache,
        private readonly LoggerInterface $logger,
        array $options,
    ) {
        $this->options = [
            'allow_insecure' => false,
            'cache_key_prefix' => 'openid_jwks',
            'cache_refresh_grace_period' => 'PT2H',
            'cache_expires_if_no_header' => 'PT10M',
            ...$options,
        ];
    }

    /**
     * Fetch the public certificates the issuer uses to sign OpenID Connect tokens (using cache).
     *
     * Uses the issuer's OpenID discovery document (at :issuer:/.well-known/openid-configuration)
     * and the JWKS document that references to build a list of the available certificates.
     *
     * The list will be cached based on the `Expires` header on the JWKS document. This time is
     * extended by the configurable `cache_refresh_grace_period`. Within the grace period we attempt
     * to fetch the new certificates, but return the cached value if we encounter any errors. After
     * the grace period (or if there is no cached value) then errors retrieving or parsing the
     * certificates will be thrown as exceptions.
     *
     * The returned data is a simple hash of `key_id (kid)` => `Firebase\JWT\Key`
     *
     * @throws CertificateDiscoveryFailedException
     */
    public function getCertificates(string $issuer): array
    {
        $this->validateIssuer($issuer);

        $cache_item = $this->checkCache($issuer);
        $prev_data = $data = $cache_item->get();

        if ($cache_item->isHit()) {
            if ($data['expires'] < new DateTimeImmutable()) {
                // Soft refresh, ignore errors
                $data = $this->tryToRefreshCertificates($issuer, $data);
            }
        } else {
            // Nothing cached
            $data = $this->fetchCertificates($issuer);
        }

        if ($data['fetched'] !== ($prev_data['fetched'] ?? null)) {
            $this->cacheResult($cache_item, $data);
        }

        return $data['certs'];
    }

    private function validateIssuer(string $issuer): void
    {
        $scheme = $this->options['allow_insecure'] ? 'https?' : 'https';

        if (preg_match('#^'.$scheme.'://.+#', $issuer)) {
            return;
        }

        throw new InvalidArgumentException(
            "Cannot auto-discover certificates for `$issuer`: must be a $scheme:// URL"
        );
    }

    /**
     * @throws \Psr\Cache\InvalidArgumentException
     */
    private function checkCache(string $issuer): CacheItemInterface
    {
        $cache_key = $this->options['cache_key_prefix'].'|'.sha1($issuer);

        return $this->cache->getItem($cache_key);
    }

    /**
     * @param array{certs: array<string, Key>, fetched: DateTimeImmutable, expires: DateTimeImmutable} $previous_cached
     *
     * @return array{certs: array<string, Key>, fetched: DateTimeImmutable, expires: DateTimeImmutable}
     */
    private function tryToRefreshCertificates(string $issuer, array $previous_cached): array
    {
        try {
            return $this->fetchCertificates($issuer);
        } catch (CertificateDiscoveryFailedException $e) {
            $this->logger->warning(
                'Using stale certs: '.$e->getMessage(),
                ['exception' => $e]
            );

            return $previous_cached;
        }
    }

    /**
     * @return array{certs: array<string, Key>, fetched: DateTimeImmutable, expires: DateTimeImmutable}
     */
    private function fetchCertificates(string $issuer): array
    {
        try {
            $discovery_url = $issuer.'/.well-known/openid-configuration';
            $jwks_resp = $this->discoverAndFetchJWKSuri($discovery_url);

            return [
                'certs' => $this->parseJWKSToCertsHash($jwks_resp),
                'fetched' => new DateTimeImmutable(),
                'expires' => $this->calculateResponseExpiryTime($jwks_resp),
            ];
        } catch (Exception $e) {
            throw new CertificateDiscoveryFailedException(
                sprintf(
                    'Failed to fetch openid certs for `%s`: [%s] %s',
                    $issuer,
                    $e::class,
                    $e->getMessage()
                ),
                $e->getCode(),
                $e
            );
        }
    }

    private function discoverAndFetchJWKSuri(string $discovery_url): ResponseInterface
    {
        $discovery = $this->guzzle->request('GET', $discovery_url);
        $discovery = json_decode($discovery->getBody(), true, flags: JSON_THROW_ON_ERROR);

        return $this->guzzle->request('GET', $discovery['jwks_uri']);
    }

    /**
     * @return array<string, Key>
     */
    private function parseJWKSToCertsHash(ResponseInterface $keys): array
    {
        $keys_json = json_decode($keys->getBody(), true, flags: JSON_THROW_ON_ERROR);

        return JWK::parseKeySet($keys_json);
    }

    private function calculateResponseExpiryTime(ResponseInterface $jwks_resp): DateTimeImmutable
    {
        $expires = $jwks_resp->getHeaderLine('Expires');

        if ($expires === '') {
            return new DateTimeImmutable()
                ->add(new DateInterval($this->options['cache_expires_if_no_header']));
        }

        $res = DateTimeImmutable::createFromFormat(DateTimeInterface::RFC1123, $expires);
        if ($res === false) {
            throw new InvalidArgumentException(
                'JWKS expires header missing or invalid ('.$expires.')'
            );
        }

        return $res;
    }

    /**
     * @param array<string, mixed> $data
     */
    private function cacheResult(CacheItemInterface $cache_item, array $data): void
    {
        $cache_item->set($data);
        $cache_item->expiresAt(
            $data['expires']->add(new DateInterval($this->options['cache_refresh_grace_period']))
        );
        $this->cache->save($cache_item);
    }
}
