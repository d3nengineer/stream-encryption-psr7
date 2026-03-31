<?php

declare(strict_types=1);

namespace Infra\StreamEncryption\Stream;

use Infra\StreamEncryption\Crypto\Decryptor;
use Infra\StreamEncryption\Crypto\Encryptor;
use Infra\StreamEncryption\Enum\MediaType;
use Psr\Http\Message\StreamInterface;

/**
 * Thin orchestration layer over stream decorators.
 *
 * StreamFactory does not normalize payloads, validate media keys, buffer streams,
 * or wrap exceptions. It only wires source streams and crypto services into
 * EncryptingStream/DecryptingStream constructors.
 *
 * Returned decorators keep the same ownership and exception semantics as direct
 * decorator construction. Factory calls are lazy: no source reads or crypto work
 * happen until the returned decorator is consumed.
 */
final class StreamFactory
{
    public function __construct(
        private readonly Encryptor $encryptor = new Encryptor(),
        private readonly Decryptor $decryptor = new Decryptor(),
    ) {
    }

    /**
     * Create an encrypting decorator for the given source stream.
     *
     * This method only constructs the decorator and passes dependencies through;
     * it does not read from the source stream eagerly.
     */
    public function encrypt(StreamInterface $source, string $mediaKey, MediaType $mediaType): EncryptingStream
    {
        return new EncryptingStream($source, $mediaKey, $mediaType, $this->encryptor);
    }

    /**
     * Create a decrypting decorator for the given source stream.
     *
     * This method only constructs the decorator and passes dependencies through;
     * it does not read from the source stream eagerly.
     */
    public function decrypt(StreamInterface $source, string $mediaKey, MediaType $mediaType): DecryptingStream
    {
        return new DecryptingStream($source, $mediaKey, $mediaType, $this->decryptor);
    }
}
