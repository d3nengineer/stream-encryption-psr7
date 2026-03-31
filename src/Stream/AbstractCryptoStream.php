<?php

declare(strict_types=1);

namespace Infra\StreamEncryption\Stream;

use Psr\Http\Message\StreamInterface;
use RuntimeException;
use Throwable;

abstract class AbstractCryptoStream implements StreamInterface
{
    private ?StreamInterface $internalStream = null;

    abstract protected function createInternalStream(): StreamInterface;

    public function __toString(): string
    {
        try {
            return (string) $this->getInternalStream();
        } catch (Throwable) {
            return '';
        }
    }

    public function close(): void
    {
        if ($this->internalStream === null) {
            return;
        }

        $internalStream = $this->internalStream;
        $this->internalStream = null;
        $internalStream->close();
    }

    public function detach()
    {
        if ($this->internalStream === null) {
            return null;
        }

        $internalStream = $this->internalStream;
        $this->internalStream = null;

        return $internalStream->detach();
    }

    public function getSize(): ?int
    {
        return $this->getInternalStream()->getSize();
    }

    public function tell(): int
    {
        return $this->getInternalStream()->tell();
    }

    public function eof(): bool
    {
        return $this->getInternalStream()->eof();
    }

    public function isSeekable(): bool
    {
        return $this->getInternalStream()->isSeekable();
    }

    public function seek(int $offset, int $whence = SEEK_SET): void
    {
        $this->getInternalStream()->seek($offset, $whence);
    }

    public function rewind(): void
    {
        $this->getInternalStream()->rewind();
    }

    public function isWritable(): bool
    {
        return false;
    }

    public function write(string $string): int
    {
        throw new RuntimeException('AbstractCryptoStream is read-only.');
    }

    public function isReadable(): bool
    {
        return $this->getInternalStream()->isReadable();
    }

    public function read(int $length): string
    {
        return $this->getInternalStream()->read($length);
    }

    public function getContents(): string
    {
        return $this->getInternalStream()->getContents();
    }

    public function getMetadata(?string $key = null)
    {
        return $this->getInternalStream()->getMetadata($key);
    }

    private function getInternalStream(): StreamInterface
    {
        return $this->internalStream ??= $this->createInternalStream();
    }
}
