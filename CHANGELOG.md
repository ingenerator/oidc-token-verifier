## Unreleased

## v2.0.0 (2026-11-26)

### Breaking changes

* `TokenConstraints` now takes one or more `TokenConstraintInterface` objects instead of a `name => value` array:
   - Replace `audience_exact` => `new AudienceExactTokenConstraint`,
     `audience_path_and_query` => `new AudiencePathAndQueryTokenConstraint`,
     `email_exact` => 'new EmailExactTokenConstraint`,
     `email_match` => `new EmailMatchTokenConstraint`.
    - Custom constraints must implement `TokenConstraintInterface`; subclassing `TokenConstraints` and overriding
      `getAllMatchers()` is no longer supported.
    - `TokenConstraints::toArray()` now returns a list of constraint objects.
    - `MockTokenVerifier::assertVerifiedOnce()` now expects a list of constraint objects, compared by value.
* All concrete classes are now `final` - replace subclasses or class-based test doubles of library classes with
  composition, or real instances of provided interfaces.
* Added native strict parameter, property and return types and phpstan tags for valid array shapes and other
  complex types.

### Other changes

* Missing or non-string claims checked by `audience_path_and_query` and `email_match`, and missing `aud` / `email`
  claims generally, now fail the constraint cleanly.
* A missing or non-string `iss` claim now explicitly fails verification.
* Malformed discovery and JWKS documents are now rejected with `CertificateDiscoveryFailedException`.
* Invalid `cache_refresh_grace_period` / `cache_expires_if_no_header` values now throw when
  `OpenIDDiscoveryCertificateProvider` is constructed.
* The certificate cache key and cached data format have changed - expect certificates to be re-fetched on first
  use after deployment: 1.x cache entries are not reused, including as a fallback if the issuer is unavailable.
  
## v1.7.0 (2026-11-18)

* Add support for guzzlehttp/guzzle ^8.3

## v1.6.0 (2026-11-04)

* Support PHP 8.5 and PHP 8.6
* Drop support for PHP 8.2 and 8.3

## v1.5.1 (2026-07-28)

* Use native json_decode instead of deprecated Guzzle utility functions

## v1.5.0 (2026-06-23)

* Support firebase/php-jwt:^7.0 - this fixes a potential security issue where the size of JWT encryption keys was not
  validated. Keys that are too short to be used securely with the specified algorithm will now cause an error. 

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
