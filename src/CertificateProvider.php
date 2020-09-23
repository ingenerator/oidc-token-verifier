<?php


namespace Ingenerator\OIDCTokenVerifier;


interface CertificateProvider
{

    public function getCertificates(string $issuer): array;
    
}
