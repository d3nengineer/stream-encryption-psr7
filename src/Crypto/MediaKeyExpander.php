<?php

declare(strict_types=1);

namespace Infra\StreamEncryption\Crypto;

use Infra\StreamEncryption\Enum\MediaType;
use Infra\StreamEncryption\Exception\InvalidMediaKeyException;
use Infra\StreamEncryption\ValueObject\ExpandedMediaKey;

final class MediaKeyExpander
{
    private const INPUT_KEY_BYTES = 32;
    private const OUTPUT_KEY_BYTES = 112;
    private const IV_BYTES = 16;
    private const CIPHER_KEY_BYTES = 32;
    private const MAC_KEY_BYTES = 32;

    public function expand(string $mediaKey, MediaType $mediaType): ExpandedMediaKey
    {
        $this->assertMediaKeyLength($mediaKey);

        $expandedKey = hash_hkdf(
            'sha256',
            $mediaKey,
            self::OUTPUT_KEY_BYTES,
            $mediaType->hkdfInfo(),
            '',
        );

        return new ExpandedMediaKey(
            iv: substr($expandedKey, 0, self::IV_BYTES),
            cipherKey: substr($expandedKey, self::IV_BYTES, self::CIPHER_KEY_BYTES),
            macKey: substr($expandedKey, self::IV_BYTES + self::CIPHER_KEY_BYTES, self::MAC_KEY_BYTES),
        );
    }

    private function assertMediaKeyLength(string $mediaKey): void
    {
        $actualLength = strlen($mediaKey);

        if ($actualLength !== self::INPUT_KEY_BYTES) {
            throw InvalidMediaKeyException::expectedLength(self::INPUT_KEY_BYTES, $actualLength);
        }
    }
}
