<?php

declare(strict_types=1);

namespace Ingenerator\OIDCTokenVerifier;

use Firebase\JWT\Key;

/**
 * @phpstan-type TCertificateKeyMap array<string, Key>
 */
interface CertificateProvider
{
    /**
     * @return TCertificateKeyMap
     */
    public function getCertificates(string $issuer): array;
}
