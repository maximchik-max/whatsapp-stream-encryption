<?php

namespace WhatsAppStreamEncryption;

class StreamHelper
{
    public const BLOCK_SIZE = 16;
    public const MAC_SIZE = 10;

    public const READ_CONTENT_BLOCK_SIZE = 4 * 1024;

    public const MEDIA_TYPE_IMAGE = 'IMAGE';
    public const MEDIA_TYPE_VIDEO = 'VIDEO';
    public const MEDIA_TYPE_AUDIO = 'AUDIO';
    public const MEDIA_TYPE_DOCUMENT = 'DOCUMENT';

    private const HKDF_INFO_MAP = [
        self::MEDIA_TYPE_IMAGE => 'WhatsApp Image Keys',
        self::MEDIA_TYPE_VIDEO => 'WhatsApp Video Keys',
        self::MEDIA_TYPE_AUDIO => 'WhatsApp Audio Keys',
        self::MEDIA_TYPE_DOCUMENT => 'WhatsApp Document Keys',
    ];

    public static function expandMediaKey(string $mediaKey, string $mediaType): array
    {
        if (!isset(self::HKDF_INFO_MAP[$mediaType])) {
            throw new \InvalidArgumentException("Invalid media type: {$mediaType}");
        }

        $info = self::HKDF_INFO_MAP[$mediaType];
        $mediaKeyExpanded = hash_hkdf('sha256', $mediaKey, 112, $info);

        return [
            'iv' => substr($mediaKeyExpanded, 0, 16),
            'cipherKey' => substr($mediaKeyExpanded, 16, 32),
            'macKey' => substr($mediaKeyExpanded, 48, 32),
            'refKey' => substr($mediaKeyExpanded, 80),
        ];
    }

    public static function calcBlocksLength(int $length): int
    {
        return (int) (StreamHelper::BLOCK_SIZE * ceil($length / StreamHelper::BLOCK_SIZE));
    } 

    public static function calculateMac(\HashContext $hashCtx): string
    {
        return substr(hash_final($hashCtx, true), 0, self::MAC_SIZE);
    }

    public static function initHashCtx(string $macKey, string $iv): \HashContext
    {
        $hashCtx = hash_init('sha256', HASH_HMAC, $macKey);
        hash_update($hashCtx, $iv);
        return $hashCtx;
    }

}
