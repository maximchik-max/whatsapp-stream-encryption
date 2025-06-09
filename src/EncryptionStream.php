<?php

namespace WhatsAppStreamEncryption;

use Psr\Http\Message\StreamInterface;
use RuntimeException;

// подписать и валидировать данные стрима при промощи HMAC мы не можем, так как для этого нужны ВСЕ данные со 
// стрима, а одно из условий - стрим мы читаем и держим в памяти БЛОКАМИ, т.е. ВСЕ данные одномоментно НЕ доступны
// исключение - весь файл поместился в один блок при кодировании и раскодировании
    
class EncryptionStream implements StreamInterface
{
    private $stream;
    private $mediaKey;
    private $mediaType;
    private $keys;
    private $position;
    private $eof;
    private $encryptedData;
    private $curIv;

    public function __construct(StreamInterface $stream, string $mediaKey, string $mediaType)
    {
        $this->stream = $stream;
        $this->mediaKey = $mediaKey;
        $this->mediaType = $mediaType;
        $this->keys = StreamHelper::expandMediaKey($mediaKey, $mediaType);
        $this->position = 0;
        $this->eof = false;
        $this->encryptedData = '';
        $this->curIv = $this->keys['iv'];
    }

    public function __toString(): string
    {
        try {
            return $this->getContents();
        } catch (\Exception $e) {
            return '';
        }
    }

    public function close(): void
    {
        $this->stream->close();
    }

    public function detach()
    {
        $this->encryptedData = '';
        return $this->stream->detach();
    }

    public function getSize(): ?int
    {
        if ($this->eof) {
            $size = $this->position;
        } else {
            $size = (1 + floor($this->stream->getSize() / StreamHelper::BLOCK_SIZE)) * StreamHelper::BLOCK_SIZE;
            $size += StreamHelper::MAC_SIZE;
        }
        return $size;
    }

    public function tell(): int
    {
        return $this->position;
    }

    public function eof(): bool
    {
        return $this->eof;
    }

    public function isSeekable(): bool
    {
        return $this->stream->isSeekable();
    }

    public function seek($offset, $whence = SEEK_SET): void
    {
        if (!$this->isSeekable()) {
            throw new RuntimeException('EncryptionStream not seekable');
        }

        if ($offset === 0 && $whence === SEEK_SET) {
            $this->position = 0;
            $this->eof = false;
            $this->curIv = $this->keys['iv'];
            $this->encryptedData = '';
            $this->stream->seek(0, $whence);
        } else {
            throw new RuntimeException('EcryptionStream only support being rewound, not arbitrary seeking.');
        }
    }

    public function rewind(): void
    {
        $this->seek(0, SEEK_SET);
    }

    public function isWritable(): bool
    {
        return false;
    }

    public function write($string): int
    {
        throw new RuntimeException('EncryptionStream is not writable');
    }

    public function isReadable(): bool
    {
        return true;
    }

    public function read($length): string
    {
        if (strlen($this->encryptedData) >= $length) {
            $data = substr($this->encryptedData, 0, $length);
            $dataLen = strlen($data);
            $this->encryptedData = substr($this->encryptedData, $dataLen);
            $this->position += $dataLen;
            return $data;
        }

        $lengthToRead = (int) (StreamHelper::BLOCK_SIZE * ceil(($length - strlen($this->encryptedData)) / StreamHelper::BLOCK_SIZE));
        $newData = $this->stream->read($lengthToRead);

        if ($newData === '') {
            $this->eof = true;
            $data = $this->encryptedData;
            $this->encryptedData = '';
            $this->position += strlen($data);
            return $data;
        }

        $padding = OPENSSL_ZERO_PADDING;
        if($this->stream->eof()) {
            $padding = 0;
        }

        $encrypted = openssl_encrypt(
            $newData,
            'aes-256-cbc',
            $this->keys['cipherKey'],
            OPENSSL_RAW_DATA | $padding,
            $this->curIv
        );

        $this->encryptedData .= $encrypted;

        if($this->stream->eof()) {
            // на самом деле мы не можем сгенерировать MAC так как для его генерации нужет
            // ВЕСЬ зашифрованный файл, а мы его целиком в памяти не храним
            // так что это нормально сработает, только если ВЕСЬ исходный файл попадет в один блок 
            // при кодировании и раскодировании 
            $this->encryptedData .= StreamHelper::generateMac($this->keys['iv'] . $this->encryptedData, $this->keys['macKey']);
        }

        $this->curIv = substr($newData, -StreamHelper::BLOCK_SIZE);

        return $this->read($length);
    }

    public function getContents(): string
    {
        $data = '';
        while(!$this->eof) {
            $data .= $this->read(StreamHelper::READ_CONTENT_BLOCK_SIZE);
        }
        return $data;
    }

    public function getMetadata($key = null)
    {
        return $this->stream->getMetadata($key);
    }
}
