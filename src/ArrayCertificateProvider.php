<?php


namespace Ingenerator\OIDCTokenVerifier;


/**
 * Simple provider for hardcoded certificates. Generally used in dev / test contexts
 */
class ArrayCertificateProvider implements CertificateProvider
{
    /**
     * @var array
     */
    private $issuer_certs;

    public function __construct(array $issuer_certs)
    {
        $this->issuer_certs = $issuer_certs;
    }

    public function getCertificates(string $issuer): array
    {
        if ( ! isset($this->issuer_certs[$issuer])) {
            throw new CertificateDiscoveryFailedException(
                'No certificates configured for `'.$issuer.'`'
            );
        }

        return $this->issuer_certs[$issuer];
    }

}
