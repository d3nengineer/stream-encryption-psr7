<?php

declare(strict_types=1);

namespace Infra\StreamEncryption\ValueObject;

final class ExpandedMediaKey
{
    public function __construct(
        public readonly string $iv,
        public readonly string $cipherKey,
        public readonly string $macKey,
    ) {
    }
}
