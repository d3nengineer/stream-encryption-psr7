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
