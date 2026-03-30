<?php

declare(strict_types=1);

namespace Infra\StreamEncryption\Exception;

use InvalidArgumentException;

final class InvalidMediaKeyException extends InvalidArgumentException
{
    public static function expectedLength(int $expected, int $actual): self
    {
        return new self(sprintf(
            'Media key must be %d bytes, got %d bytes.',
            $expected,
            $actual,
        ));
    }
}
