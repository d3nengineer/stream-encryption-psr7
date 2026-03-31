<?php

declare(strict_types=1);

namespace Infra\StreamEncryption\Stream;

use GuzzleHttp\Psr7\Utils;
use Infra\StreamEncryption\Crypto\Decryptor;
use Infra\StreamEncryption\Enum\MediaType;
use Psr\Http\Message\StreamInterface;
use RuntimeException;

final class DecryptingStream extends AbstractCryptoStream
{
    private ?string $plaintext = null;

    public function __construct(
        private readonly StreamInterface $source,
        private readonly string $mediaKey,
        private readonly MediaType $mediaType,
        private readonly Decryptor $decryptor = new Decryptor(),
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
        return Utils::streamFor($this->getOrCreatePlaintext());
    }

    private function getOrCreatePlaintext(): string
    {
        if ($this->plaintext !== null) {
            return $this->plaintext;
        }

        $payload = $this->readSourcePayload();
        $this->plaintext = $this->decryptor->decrypt($payload, $this->mediaKey, $this->mediaType);

        return $this->plaintext;
    }

    private function readSourcePayload(): string
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
