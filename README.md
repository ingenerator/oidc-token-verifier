oidc-token-verifier is a lightweight PHP validator
for [OIDC ID Tokens](https://openid.net/specs/openid-connect-core-1_0.html#IDToken)
as used in the [OpenID Connect](https://openid.net/connect/) protocol.

[![Tests](https://github.com/ingenerator/oidc-token-verifier/workflows/Run%20tests/badge.svg)](https://github.com/ingenerator/cloud-tasks-wrapper/actions)

`$> composer require ingenerator/oidc-token-verifier`

# Usage of OIDC tokens

In the full OpenID Connect specification, the ID Token forms part of a multi-step end-user authorization flow. This is a
similar concept to using OAuth to authenticate users based on a third-party auth provider.

However, OIDC Tokens can also be used for lightweight server-to-server authentication. For example, they can be used to
authorise HTTP requests from [Google Cloud Tasks](https://cloud.google.com/tasks/docs/creating-http-target-tasks#token).

Server-to-Server flows like this do not require the full OpenID Connect protocol. They only require the ability to
verify the ID Token itself. The ID Token is a [JWT](https://jwt.io/), which is cryptographically signed by the issuer.
Authenticating the token involves verifying the signature against the issuer's public keys, which are available from a
well-known HTTP endpoint, and then performing some checks on the content of the token itself.

Although there are number of PHP JWT libraries, we have struggled to find any that support the certificate discovery /
claim assertion phases of the process. This library fills that gap.

Note that all cryptographic / JWT-level operations are delegated to the firebase/php-jwt package. Also note that at
present we only support RSA keys and the RS256 token algorithm.

# Usage

You validate a token with the `OIDCTokenVerifier`. There is also a `MockTokenVerifier` using the same interface for unit
testing purposes.

In the simplest case you would do something like this:

```php
// Where the AUTHORIZATION header is `Bearer {token}`
use Google\Auth\Cache\SysVCacheItemPool;use Ingenerator\OIDCTokenVerifier\OIDCTokenVerifier;use Ingenerator\OIDCTokenVerifier\OpenIDDiscoveryCertificateProvider;use Ingenerator\OIDCTokenVerifier\TokenConstraints;use Ingenerator\OIDCTokenVerifier\TokenVerificationResult;use Psr\Log\NullLogger;use test\mock\Ingenerator\OIDCTokenVerifier\Cache\MockCacheItemPool;
[$bearer, $jwt] = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
$verifier = new OIDCTokenVerifier(
    new OpenIDDiscoveryCertificateProvider(
        new \GuzzleHttp\Client, 
        // Any psr-6 CacheItemPoolInterface implementation, used for caching issuer certificates
        new CacheItemPoolInterface,  
        new NullLogger // Any PSR logger
    ),
    // You *must* explicitly provide the issuer your application expects to receive tokens from.
    // The verifier will *only* request certificates from this issuer. Otherwise, any third party could set up an HTTP 
    // certificate endpoint and send you tokens signed by them.
    //
    // If your application may receive tokens from more than one issuer, you will need to (securely) identify the issuer
    // of a specific token and then create an appropriate verifier.
    // 
    'https://accounts.google.com'
);

// See below for details of the TokenConstraints argument
$result = $verifier->verify($jwt, TokenConstraints::signatureCheckOnly()); 

// You can either interrogate the result like this
if ( ! $result->isVerified()) {
    echo "NOT AUTHORISED\n";
    echo $result->getFailure()->getMessage()."\n";
} else {
    // The JWT payload is available from the result object
    echo "Authorised as ".$result->getPayload()->email."\n";
}

// Or if you'd prefer to throw an exception on failed auth this will:
// - Throw TokenVerificationFailedException if verification failed
// - Return the verified result if successful
$result = TokenVerificationResult::enforce($result);
```

### Extra constraints

By default, the library only performs basic JWT validation - signature, expiry time / not before time etc.

For security, **additional verification is almost always required**. For example, any Google Cloud Platform user can
produce a valid JWT signed by `https://accounts.google.com` so you would usually want to authorize based on both
the `audience` (that the token was created for) and the `email` (the service account used to create it).

The library provides support for these common constraints out of the box:

```php
$verifier->verify($jwt, new TokenConstraints([
    // The audience (`aud` claim) of the JWT must exactly match this value
    // Some google services use the URL that is being called. Others provide a custom value - an app/client ID, etc
    'audience_exact' => 'https://my.app.com/task-handler-url',
    
    // The audience (`aud` claim) of the JWT is a URL and the path (and querystring if any) must match this value
    // In some loadbalanced environments it's hard to detect the external protocol or hostname from an incoming
    // request - e.g. a request to https://my.app.loadbalancer may appear to PHP as being to http://app.cluster.local.
    // Although this can be worked round with custom headers (X_FORWARDED_PROTO etc) these introduce other risks and
    // ultimately couple the app implementation to architectural concerns. In many cases, it's enough to verify the
    // the resource the token was generated for (path and querystring) without caring about scheme and hostname. This
    // alone prevents using a stolen token to perform a different operation. Cross-environment / cross-site attacks
    // are instead protected by using different service accounts for each separate logical system so that e.g a token
    // generated for QA cannot ever authorise that operation in production regardless of the hostnames used.
    'audience_path_and_query' => 'http://appserver.internal/action?record_id=15',

    // The JWT must contain an `email` claim, and it must exactly match this value
    'email_exact' => 'my-service-account@myproject.serviceaccount.test',
    
    // The JWT must contain an `email` claim, and it must exactly match one of these values
    // Useful when you have a short list of service accounts that may be allowed to call your endpoint    
    'email_exact' => [
        'my-service-account@myproject.serviceaccount.test',
        'my-service-account@myotherproject.serviceaccount.test',
    ],
    
    // The JWT must contain an `email` claim, and it must match this regex
    // Useful when you want to e.g. authorize all service accounts in a particular domain - use with caution!
    'email_match' => '/@myproject.serviceaccount.test$/'  
]));
```

You can easily support additional custom constraints e.g. to verify additional custom claims:

```php
class MyTokenConstraints extends TokenConstraints {
    
    protected static function getAllMatchers(): array {
        $matchers = parent::getAllMatchers();
        // Constraint matchers are an array of {name} => boolean function indicating if the payload matches
        $matchers['user_role_contains'] = function (\stdClass $payload, string $expect) {
            // $payload is the decoded JWT
            // We check it has a custom claim ->user_roles as an array of roles
            return in_array($expect, $payload->user_roles ?? [], TRUE);       
        };
        return $matchers;    
    }
}

$verifier->verify($jwt, new MyTokenConstraints([
    'audience_exact'     => 'https://foo.bar/something',
    'user_role_contains' => 'administrator'
]));

```

If your app handles authorization separately (or for testing purposes) you can use the
`TokenConstraints::signatureCheckOnly()` method to create an empty set of constraints.

### Certificate discovery and caching

By default, the library uses the OpenIDDicoveryCertificateProvider to dynamically fetch public certificates for a given
issuer. This uses the `{issuer}/.well-known/openid-configuration` discovery document to find the issuer's JWKS url.
Certificates are then fetched from the JWKS url, decoded and cached (in a PSR-6 cache) for subsequent requests.

For obvious reasons, both the discovery document and the JWKS **must** be served over HTTPS. In development environments
e.g. if working against an emulator, you may not have HTTPS available. In this case, pass the
`allow_insecure => TRUE` option to enable fetching certs over HTTP.

The cache lifetime is based on the `Expires` header of the JWKS response. Note that we do not cache (or pay attention
to) the cache headers on the OpenID Discovery Document itself. If an issuer changes their `jwks_uri` this will not be
detected until the JWKS response itself expires.

Occasionally, network / issuer errors might occur when fetching or refreshing certificates. Since JWKS change fairly
infrequently, the default behaviour is to log failures but use a stale cache value for up to 2 hours. This can be
configured with the `cache_refresh_grace_period` option to OpenIDDiscoveryCertificateProvider.

HTTP-based discovery is the simplest and recommended solution, as it allows for issuer-controlled certificate and key
rotation. However, an `ArrayCertificateProvider` is available (or you can provide your own implementation) if you would
prefer to work with a hardcoded / alternative source of issuer certificates.

# Contributing

Contributions are welcome but please contact us (e.g. by filing an issue) before you start work on anything substantial
: we may have particular requirements / opinions that differ from yours.

# Contributors

This package has been sponsored by [inGenerator Ltd](http://www.ingenerator.com)

* Andrew Coulton [acoulton](https://github.com/acoulton) - Lead developer

# Licence

Licensed under the [BSD-3-Clause Licence](LICENSE)
