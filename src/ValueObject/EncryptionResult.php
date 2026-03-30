<?php

declare(strict_types=1);

namespace Infra\StreamEncryption\ValueObject;

final class EncryptionResult
{
    public readonly string $payload;

    public function __construct(
        public readonly string $ciphertext,
        public readonly string $mac,
    ) {
        $this->payload = $this->ciphertext . $this->mac;
    }
}
