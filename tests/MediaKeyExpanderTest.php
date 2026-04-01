<?php

declare(strict_types=1);

namespace Infra\StreamEncryption\Tests;

use Infra\StreamEncryption\Crypto\MediaKeyExpander;
use Infra\StreamEncryption\Enum\MediaType;
use Infra\StreamEncryption\Exception\InvalidMediaKeyException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class MediaKeyExpanderTest extends TestCase
{
    public function testItDerivesDeterministicKeysForTheSameInput(): void
    {
        $expander = new MediaKeyExpander();
        $mediaKey = str_repeat('k', 32);

        $first = $expander->expand($mediaKey, MediaType::IMAGE);
        $second = $expander->expand($mediaKey, MediaType::IMAGE);

        $this->assertSame($first->iv, $second->iv);
        $this->assertSame($first->cipherKey, $second->cipherKey);
        $this->assertSame($first->macKey, $second->macKey);
    }

    public function testItUsesMediaTypeAsDerivationContext(): void
    {
        $expander = new MediaKeyExpander();
        $mediaKey = str_repeat('k', 32);

        $imageKey = $expander->expand($mediaKey, MediaType::IMAGE);
        $videoKey = $expander->expand($mediaKey, MediaType::VIDEO);

        $this->assertNotSame($imageKey->iv, $videoKey->iv);
        $this->assertNotSame($imageKey->cipherKey, $videoKey->cipherKey);
        $this->assertNotSame($imageKey->macKey, $videoKey->macKey);
    }

    #[DataProvider('invalidMediaKeyLengthProvider')]
    public function testItRejectsMediaKeysOutside32Bytes(string $mediaKey): void
    {
        $expander = new MediaKeyExpander();

        $this->expectException(InvalidMediaKeyException::class);

        $expander->expand($mediaKey, MediaType::IMAGE);
    }

    public function testItReturnsExpectedSegmentLengths(): void
    {
        $expander = new MediaKeyExpander();
        $expandedKey = $expander->expand(str_repeat('k', 32), MediaType::AUDIO);

        $this->assertSame(16, strlen($expandedKey->iv));
        $this->assertSame(32, strlen($expandedKey->cipherKey));
        $this->assertSame(32, strlen($expandedKey->macKey));
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function invalidMediaKeyLengthProvider(): array
    {
        return [
            'empty-0' => [''],
            'short-31' => [random_bytes(31)],
            'long-33' => [random_bytes(33)],
        ];
    }
}
