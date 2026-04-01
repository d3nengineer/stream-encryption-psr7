<?php

declare(strict_types=1);

namespace Infra\StreamEncryption\Crypto;

use Infra\StreamEncryption\Exception\IntegrityException;

final class Hmac
{
    public const MAC_BYTES = 10;

    public function sign(string $iv, string $ciphertext, string $macKey): string
    {
        $fullMac = hash_hmac('sha256', $iv . $ciphertext, $macKey, true);

        return substr($fullMac, 0, self::MAC_BYTES);
    }

    public function verify(string $iv, string $ciphertext, string $mac, string $macKey): void
    {
        $expectedMac = $this->sign($iv, $ciphertext, $macKey);

        if (!hash_equals($expectedMac, $mac)) {
            throw new IntegrityException('Encrypted payload integrity check failed.');
        }
    }
}
