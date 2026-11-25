<?php

namespace Ingenerator\OIDCTokenVerifier;

/**
 * Simple provider for hardcoded certificates. Generally used in dev / test contexts.
 *
 * @phpstan-import-type TCertificateKeyMap from CertificateProvider
 */
final class ArrayCertificateProvider implements CertificateProvider
{
    /**
     * @param array<string, TCertificateKeyMap> $issuer_certs
     */
    public function __construct(
        private array $issuer_certs,
    ) {
    }

    public function getCertificates(string $issuer): array
    {
        if (!isset($this->issuer_certs[$issuer])) {
            throw new CertificateDiscoveryFailedException(
                'No certificates configured for `'.$issuer.'`'
            );
        }

        return $this->issuer_certs[$issuer];
    }
}
