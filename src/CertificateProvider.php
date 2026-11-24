<?php

declare(strict_types=1);

namespace Ingenerator\OIDCTokenVerifier;

interface CertificateProvider
{
    public function getCertificates(string $issuer): array;
}
