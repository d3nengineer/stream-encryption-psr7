<?php

declare(strict_types=1);

namespace Infra\StreamEncryption\Crypto;

use Infra\StreamEncryption\Exception\IntegrityException;

final class Hmac
{
    public const MAC_BYTES = 32;

    public function sign(string $ciphertext, string $macKey): string
    {
        return hash_hmac('sha256', $ciphertext, $macKey, true);
    }

    public function verify(string $ciphertext, string $mac, string $macKey): void
    {
        $expectedMac = $this->sign($ciphertext, $macKey);

        if (!hash_equals($expectedMac, $mac)) {
            throw new IntegrityException('Encrypted payload integrity check failed.');
        }
    }
}
