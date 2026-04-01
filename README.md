# Stream Encryption PSR-7

`d3nengineer/stream-encryption-psr7` is a PHP 8.2+ library that exposes lazy PSR-7 stream decorators for media encryption and decryption using AES-CBC, HKDF-SHA256, and HMAC-SHA256.

## Installation

```bash
composer require d3nengineer/stream-encryption-psr7
```

## Recommended Entry Point

Use `Infra\StreamEncryption\Stream\StreamFactory` for the common happy path. It creates lazy encrypting and decrypting decorators without changing the underlying stream behavior or exception model.

```php
<?php

use GuzzleHttp\Psr7\Utils;
use Infra\StreamEncryption\Enum\MediaType;
use Infra\StreamEncryption\Stream\StreamFactory;

$factory = new StreamFactory();
$mediaKey = random_bytes(32);

$encrypted = $factory->encrypt(
    Utils::streamFor("binary\x00payload"),
    $mediaKey,
    MediaType::IMAGE,
);

$decrypted = $factory->decrypt(
    Utils::streamFor((string) $encrypted),
    $mediaKey,
    MediaType::IMAGE,
);

$plaintext = (string) $decrypted;
```

## Supported Runtime

- PHP 8.2+
- `psr/http-message` ^1.0 or ^2.0
- `guzzlehttp/psr7` ^2.0

## Verification

Run the same checks locally that the repository uses for release-readiness:

```bash
composer validate --strict
find src tests -name '*.php' -print0 | xargs -0 -n1 php -l
vendor/bin/phpunit
```

## More Details

Package behavior and operational guarantees that do not belong on the landing page live in [docs/usage.md](docs/usage.md).
