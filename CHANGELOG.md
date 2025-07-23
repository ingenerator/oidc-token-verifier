## Unreleased

## v1.4.0 (2025-07-22)

* Support PHP 8.4

## v1.3.0 (2025-02-03)

* Drop support for PHP 8.0 and 8.1
* Support JWKS endpoints that do not provide an `Expires` header - cache for 10 minutes by default (customisable).

## v1.2.0 (2024-10-01)

* Support PHP 8.3

## v1.1.0 (2023-11-06)

* Support newer versions of PSR cache and log interfaces

## v1.0.0 (2023-10-26)

* Upgrade to firebase/php-jwt: ^6.0 - in most cases this will not affect external users of this library. However, if you are directly using the included `CertificateProvider` classes note that these now return an array of `Firebase\JWT\Key` objects, not strings.

## v0.3.0 (2022-10-17)

* Support PHP 8.1 and PHP 8.2

## v0.2.0 (2021-11-01)

* Support PHP 8.0

## v0.1.1 (2021-01-18)

* Add new `audience_path_and_query` token constraint matcher to ignore protocol and hostname mismatches on URL audiences

## v0.1.0 (2020-12-08)

* Initial version
