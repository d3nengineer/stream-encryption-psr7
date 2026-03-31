# Stream encryption psr7

PSR-7 stream decorators for media encryption (AES-CBC + HKDF + HMAC).

## EncryptingStream

`Infra\StreamEncryption\Stream\EncryptingStream` lazily reads a source PSR-7 stream,
encrypts the source bytes with `Encryptor`, and exposes encrypted bytes as a read-only PSR-7 stream.

### Constructor

```php
new EncryptingStream(
    StreamInterface $source,
    string $mediaKey,
    MediaType $mediaType,
    Encryptor $encryptor = new Encryptor(),
)
```

- `source`: plaintext source stream.
- `mediaKey`: 32-byte media key used for HKDF expansion.
- `mediaType`: media context (`IMAGE`, `VIDEO`, `AUDIO`, `DOCUMENT`).
- `encryptor`: optional custom encryptor implementation.

### Usage

```php
<?php

use GuzzleHttp\Psr7\Utils;
use Infra\StreamEncryption\Crypto\Decryptor;
use Infra\StreamEncryption\Enum\MediaType;
use Infra\StreamEncryption\Stream\EncryptingStream;

$mediaKey = random_bytes(32);
$plaintextSource = Utils::streamFor("binary\x00payload");

$encryptingStream = new EncryptingStream(
    $plaintextSource,
    $mediaKey,
    MediaType::IMAGE,
);

$payload = (string) $encryptingStream; // ciphertext || mac

$decryptor = new Decryptor();
$plaintext = $decryptor->decrypt($payload, $mediaKey, MediaType::IMAGE);
```

### Payload Format

- Output bytes are `ciphertext || mac`.
- The MAC is HMAC-SHA256 over ciphertext.
- Decrypt with `Decryptor` using the same media key and media type.

### Source Ownership And Lifecycle

- `EncryptingStream` owns the source stream lifecycle.
- Calling `close()` closes both the internal encrypted stream and the source stream.
- Calling `detach()` detaches the internal encrypted stream resource (if initialized) and also detaches the source stream.
- Repeated `close()`/`detach()` calls are safe and idempotent.

### Source Consumption Contract

- Seekable source: `EncryptingStream` rewinds and encrypts from the beginning.
- Non-seekable source: `EncryptingStream` encrypts remaining bytes from the current cursor position.
- Pre-consumed non-seekable sources can produce an encrypted payload of an empty plaintext.

### Memory Tradeoff

- Encryption materializes the full encrypted payload in memory once and reuses it for subsequent reads.
- For very large payloads, account for full-buffer memory usage.

## DecryptingStream

`Infra\StreamEncryption\Stream\DecryptingStream` lazily reads an encrypted PSR-7 stream,
authenticates and decrypts the payload with `Decryptor`, and exposes plaintext bytes as a read-only PSR-7 stream.

### Constructor

```php
new DecryptingStream(
    StreamInterface $source,
    string $mediaKey,
    MediaType $mediaType,
    Decryptor $decryptor = new Decryptor(),
)
```

- `source`: encrypted payload stream containing `ciphertext || mac`.
- `mediaKey`: 32-byte media key used for HKDF expansion.
- `mediaType`: media context (`IMAGE`, `VIDEO`, `AUDIO`, `DOCUMENT`).
- `decryptor`: optional custom decryptor implementation.

### Usage

```php
<?php

use GuzzleHttp\Psr7\Utils;
use Infra\StreamEncryption\Crypto\Encryptor;
use Infra\StreamEncryption\Enum\MediaType;
use Infra\StreamEncryption\Stream\DecryptingStream;

$mediaKey = random_bytes(32);
$encryptor = new Encryptor();
$result = $encryptor->encrypt("binary\x00payload", $mediaKey, MediaType::IMAGE);

$decryptingStream = new DecryptingStream(
    Utils::streamFor($result->payload),
    $mediaKey,
    MediaType::IMAGE,
);

$plaintext = (string) $decryptingStream;
```

### Payload Format And Validation

- Input bytes must be `ciphertext || mac`.
- Integrity verification happens before decryption.
- Media key and media type must match the payload that produced the ciphertext.
- Crypto-layer exceptions are propagated unchanged so integrity and key failures stay explicit.

### Source Ownership And Lifecycle

- `DecryptingStream` owns the encrypted source stream lifecycle.
- Calling `close()` closes both the internal plaintext stream and the encrypted source stream.
- Calling `detach()` detaches the internal plaintext resource (if initialized) and also detaches the source stream.
- Repeated `close()`/`detach()` calls are safe and idempotent.

### Source Consumption Contract

- Seekable source: `DecryptingStream` rewinds and decrypts from the beginning.
- Non-seekable source: `DecryptingStream` decrypts remaining bytes from the current cursor position.
- Pre-consumed or truncated non-seekable payloads can fail integrity validation because the full `ciphertext || mac` payload is no longer available.

### Memory Tradeoff

- Decryption materializes the full plaintext in memory once and reuses it for subsequent reads.
- For very large payloads, account for full-buffer memory usage.

### Diagnostics Stance

- The library favors transparent exceptions and focused PHPUnit coverage over runtime logger coupling.
- Constructor guards, source-read boundaries, and crypto failures remain explicit so diagnostics can be added later without changing control flow.
