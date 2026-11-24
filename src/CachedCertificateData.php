<?php

declare(strict_types=1);

namespace Ingenerator\OIDCTokenVerifier;

use DateTimeImmutable;
use Firebase\JWT\Key;

/**
 * @internal
 */
final readonly class CachedCertificateData
{
    public const string VERSION = 'v2';

    /**
     * @param array<string, Key> $certs
     */
    public function __construct(
        public array $certs,
        public DateTimeImmutable $fetched,
        public DateTimeImmutable $expires,
    ) {
    }
}
