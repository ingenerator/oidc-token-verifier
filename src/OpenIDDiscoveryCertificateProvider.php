<?php


namespace Ingenerator\OIDCTokenVerifier;


use DateInterval;
use DateTimeImmutable;
use DateTimeInterface;
use Exception;
use Firebase\JWT\JWK;
use GuzzleHttp\ClientInterface;
use InvalidArgumentException;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Http\Message\ResponseInterface;
use function array_merge;
use function get_class;
use function openssl_pkey_free;
use function openssl_pkey_get_details;
use function preg_match;
use function sprintf;

/**
 * Provides the certificates required to validate OpenID Connect tokens by fetching the discovery /
 * jwk document for the issuer
 *
 */
class OpenIDDiscoveryCertificateProvider implements CertificateProvider
{
    /**
     * @var ClientInterface
     */
    private $guzzle;

    /**
     * @var \Psr\Cache\CacheItemPoolInterface
     */
    private $cache;

    /**
     * @var array
     */
    private $options;

    /**
     * Options:
     *
     *   * cache_key_prefix - the prefix to apply to cache keys to keep them separate from other code
     *   * cache_key_refresh_grace_period - how long to ignore errors and return a stale value if the certs cant be refreshed
     *
     * @param \GuzzleHttp\ClientInterface       $guzzle
     * @param \Psr\Cache\CacheItemPoolInterface $cache
     * @param array                             $options
     */
    public function __construct(
        ClientInterface $guzzle,
        CacheItemPoolInterface $cache,
        array $options
    ) {
        $this->guzzle  = $guzzle;
        $this->cache   = $cache;
        $this->options = array_merge(
            [
                'cache_key_prefix'           => 'openid_jwks',
                'cache_refresh_grace_period' => 'PT2H'
            ],
            $options
        );
    }

    /**
     * Fetch the public certificates the issuer uses to sign OpenID Connect tokens (using cache)
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
     * The returned data is a simple hash of `key_id (kid)` => `{certificate string in PEM format}`
     *
     * @param string $issuer
     *
     * @return string[]
     * @throws \Ingenerator\OIDCTokenVerifier\CertificateDiscoveryFailedException
     */
    public function getCertificates(string $issuer): array
    {
        if ( ! preg_match('#^https://.+#', $issuer)) {
            throw new InvalidArgumentException(
                'Cannot auto-discover certificates: issuer must be a URL'
            );
        }

        $cache_item = $this->checkCache($issuer);
        $prev_data  = $data = $cache_item->get();

        if ($cache_item->isHit()) {
            if ($data['expires'] < new DateTimeImmutable) {
                // Soft refresh, ignore errors
                $data = $this->tryToRefreshCertificates($issuer, $data);
            }
        } else {
            // Nothing cached
            $data = $this->fetchCertificates($issuer);
        }

        if ($data['fetched'] !== ($prev_data['fetched'] ?? NULL)) {
            $this->cacheResult($cache_item, $data);
        }

        return $data['certs'];
    }

    /**
     * @param string $issuer
     *
     * @return \Psr\Cache\CacheItemInterface
     * @throws \Psr\Cache\InvalidArgumentException
     */
    private function checkCache(string $issuer): CacheItemInterface
    {
        $cache_key = $this->options['cache_key_prefix'].'|'.sha1($issuer);

        return $this->cache->getItem($cache_key);
    }

    private function tryToRefreshCertificates(string $issuer, array $previous_cached): array
    {
        try {
            return $this->fetchCertificates($issuer);
        } catch (CertificateDiscoveryFailedException $e) {
            // @todo: Log it
            return $previous_cached;
        }
    }

    private function fetchCertificates(string $issuer): array
    {
        try {
            $discovery_url = $issuer.'/.well-known/openid-configuration';
            $jwks_resp     = $this->discoverAndFetchJWKSuri($discovery_url);

            return [
                'certs'   => $this->parseJWKSToCertsHash($jwks_resp),
                'fetched' => new DateTimeImmutable,
                'expires' => $this->calculateResponseExpiryTime($jwks_resp)
            ];
        } catch (Exception $e) {
            throw new CertificateDiscoveryFailedException(
                sprintf(
                    'Failed to fetch openid certs for `%s`: [%s] %s',
                    $issuer,
                    get_class($e),
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
        $discovery = \GuzzleHttp\json_decode($discovery->getBody(), TRUE);

        return $this->guzzle->request('GET', $discovery['jwks_uri']);
    }

    private function parseJWKSToCertsHash(ResponseInterface $keys): array
    {
        $keys_json = \GuzzleHttp\json_decode($keys->getBody(), TRUE);

        $key_resources = JWK::parseKeySet($keys_json);
        $certs         = [];
        foreach ($key_resources as $kid => $cert) {
            $certs[$kid] = openssl_pkey_get_details($cert)['key'];
            openssl_pkey_free($cert);
        }

        return $certs;
    }

    private function calculateResponseExpiryTime(ResponseInterface $jwks_resp): DateTimeImmutable
    {
        $expires = $jwks_resp->getHeaderLine('Expires');

        $res = DateTimeImmutable::createFromFormat(DateTimeInterface::RFC1123, $expires);
        if ($res === FALSE) {
            throw new InvalidArgumentException(
                'JWKS expires header missing or invalid ('.$expires.')'
            );
        }

        return $res;
    }

    private function cacheResult(CacheItemInterface $cache_item, array $data): void
    {
        $cache_item->set($data);
        $cache_item->expiresAt(
            $data['expires']->add(new DateInterval($this->options['cache_refresh_grace_period']))
        );
        $this->cache->save($cache_item);
    }
}
