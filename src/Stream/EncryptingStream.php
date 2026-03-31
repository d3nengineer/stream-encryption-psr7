<?php

declare(strict_types=1);

namespace Infra\StreamEncryption\Stream;

use GuzzleHttp\Psr7\Utils;
use Infra\StreamEncryption\Crypto\Encryptor;
use Infra\StreamEncryption\Enum\MediaType;
use Psr\Http\Message\StreamInterface;
use RuntimeException;

final class EncryptingStream extends AbstractCryptoStream
{
    private ?string $encryptedPayload = null;

    public function __construct(
        private readonly StreamInterface $source,
        private readonly string $mediaKey,
        private readonly MediaType $mediaType,
        private readonly Encryptor $encryptor = new Encryptor(),
    ) {
        if (!$this->source->isReadable()) {
            throw new RuntimeException('Source stream must be readable.');
        }
    }

    public function close(): void
    {
        parent::close();
        $this->source->close();
    }

    public function detach()
    {
        $detachedInternal = parent::detach();
        $this->source->detach();

        return $detachedInternal;
    }

    protected function createInternalStream(): StreamInterface
    {
        return Utils::streamFor($this->getOrCreateEncryptedPayload());
    }

    private function getOrCreateEncryptedPayload(): string
    {
        if ($this->encryptedPayload !== null) {
            return $this->encryptedPayload;
        }

        $plaintext = $this->readSourcePlaintext();
        $result = $this->encryptor->encrypt($plaintext, $this->mediaKey, $this->mediaType);
        $this->encryptedPayload = $result->ciphertext . $result->mac;

        return $this->encryptedPayload;
    }

    private function readSourcePlaintext(): string
    {
        if (!$this->source->isReadable()) {
            throw new RuntimeException('Source stream is not readable.');
        }

        if ($this->source->isSeekable()) {
            $this->source->rewind();
        }

        return $this->source->getContents();
    }
}
