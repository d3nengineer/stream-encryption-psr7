# Usage Notes

## API Surface

- `Infra\StreamEncryption\Stream\StreamFactory` is the recommended entry point for most consumers.
- `Infra\StreamEncryption\Stream\EncryptingStream` and `Infra\StreamEncryption\Stream\DecryptingStream` remain available when you want to construct decorators directly.
- Factory calls stay lazy: no source reads or crypto work happen until the returned decorator is consumed.

## Payload Contract

- Encrypted payloads use the `ciphertext || mac` format.
- The MAC is an HMAC-SHA256 over the ciphertext bytes.
- Decryption verifies integrity before attempting AES-CBC decryption.
- Media key and media type must match the payload that produced the ciphertext.

## Media Key Requirements

- Media keys must be 32 raw bytes.
- Media type participates in HKDF expansion context.
- Invalid media keys and integrity failures are surfaced through dedicated package exceptions instead of generic wrappers.

## Stream Semantics

- Seekable sources are rewound and processed from the beginning.
- Non-seekable sources are processed from the current cursor position.
- Pre-consumed non-seekable decrypting sources can fail integrity validation because the full payload is no longer available.
- Returned decorators preserve normal PSR-7 read delegation such as `read()`, `getContents()`, `rewind()`, `tell()`, `eof()`, and `getMetadata()`.

## Lifecycle Ownership

- `EncryptingStream` owns the plaintext source stream lifecycle.
- `DecryptingStream` owns the encrypted source stream lifecycle.
- Calling `close()` closes the internal materialized stream and the wrapped source stream.
- Calling `detach()` detaches both the internal stream resource, when initialized, and the wrapped source stream.

## Memory Tradeoff

- Encryption and decryption materialize the full derived payload in memory once and then reuse it for subsequent reads.
- For large payloads, plan for full-buffer memory usage.

## Exception Boundaries

- `StreamFactory` does not normalize payloads, buffer streams, or wrap exceptions.
- Crypto-layer failures propagate unchanged so integrity, media-key, and decryption failures stay explicit.
- Constructor guards still reject unreadable source streams immediately.
