<?php

declare(strict_types=1);

namespace Infra\StreamEncryption\Crypto;

use Infra\StreamEncryption\Enum\MediaType;
use Infra\StreamEncryption\Exception\IntegrityException;

final class Decryptor
{
    public function __construct(
        private readonly MediaKeyExpander $mediaKeyExpander = new MediaKeyExpander(),
        private readonly AesCbc $aesCbc = new AesCbc(),
        private readonly Hmac $hmac = new Hmac(),
    ) {
    }

    public function decrypt(string $payload, string $mediaKey, MediaType $mediaType): string
    {
        if (strlen($payload) <= Hmac::MAC_BYTES) {
            throw new IntegrityException('Encrypted payload is too short to contain ciphertext and MAC.');
        }

        $expandedKey = $this->mediaKeyExpander->expand($mediaKey, $mediaType);
        $ciphertext = substr($payload, 0, -Hmac::MAC_BYTES);
        $mac = substr($payload, -Hmac::MAC_BYTES);

        $this->hmac->verify($ciphertext, $mac, $expandedKey->macKey);

        return $this->aesCbc->decrypt($ciphertext, $expandedKey->cipherKey, $expandedKey->iv);
    }
}
