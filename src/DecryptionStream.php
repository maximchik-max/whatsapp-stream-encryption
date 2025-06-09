<?php

namespace WhatsAppStreamEncryption;

use Psr\Http\Message\StreamInterface;
use RuntimeException;

// подписать и валидировать данные стрима при промощи HMAC мы не можем, так как для этого нужны ВСЕ данные со 
// стрима, а одно из условий - стрим мы читаем и держим в памяти БЛОКАМИ, т.е. ВСЕ данные одномоментно НЕ доступны
// исключение - весь файл поместился в один блок при кодировании и раскодировании

class DecryptionStream implements StreamInterface
{
    private $stream;
    private $mediaKey;
    private $mediaType;
    private $keys;
    private $position;
    private $eof;
    private $decryptedData;
    private $curIv;
    private $lastPart;

    public function __construct(StreamInterface $stream, string $mediaKey, string $mediaType)
    {
        $this->stream = $stream;
        $this->mediaKey = $mediaKey;
        $this->mediaType = $mediaType;
        $this->keys = StreamHelper::expandMediaKey($mediaKey, $mediaType);
        $this->position = 0;
        $this->eof = false;
        $this->decryptedData = '';
        $this->lastPart = '';
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
        $this->decryptedData = '';
        $this->lastPart = '';
        return $this->stream->detach();
    }

    public function getSize(): ?int
    {
        // нельзя получить реальный размер данных до их полной расшифровки,
        // т.к. в последнем блоке может содержаться padding,
        // о котором можно узнать только после расшифровки последнего блока,
        // расшифровка которого, в свою очередь, зависит от расшифровки всех предыдуших блоков
        if (!$this->eof) {
            return null;
        }
        return strlen($this->position);
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
            throw new RuntimeException('DecryptionStream not seekable');
        }

        if ($offset === 0 && $whence === SEEK_SET) {
            $this->position = 0;
            $this->eof = false;
            $this->curIv = $this->keys['iv'];
            $this->decryptedData = '';
            $this->lastPart = '';
            $this->stream->seek(0, $whence);
        } else {
            throw new RuntimeException('DecryptionStream only support being rewound, not arbitrary seeking.');
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
        throw new RuntimeException('DecryptionStream is not writable');
    }

    public function isReadable(): bool
    {
        return true;
    }

    public function read($length): string
    {
        if (strlen($this->decryptedData) >= $length) {
            $data = substr($this->decryptedData, 0, $length);
            $dataLen = strlen($data);
            $this->decryptedData = substr($this->decryptedData, $dataLen);
            $this->position += $dataLen;
            return $data;
        }

        $lengthToRead = (int) (StreamHelper::BLOCK_SIZE * ceil(($length - strlen($this->decryptedData)) / StreamHelper::BLOCK_SIZE));
        $newData = $this->lastPart . $this->stream->read($lengthToRead);
        $this->lastPart = $this->stream->read(StreamHelper::BLOCK_SIZE);

        if ($newData === '') {
            $this->eof = true;
            $data = $this->decryptedData;
            $this->decryptedData = '';
            $this->position += strlen($data);
            return $data;
        }

        $padding = OPENSSL_ZERO_PADDING;
        if($this->stream->eof()) {
            if (strlen($this->lastPart) === StreamHelper::MAC_SIZE) {
                $mac = $this->lastPart;
            } else {
                $mac = substr($newData, -StreamHelper::MAC_SIZE);
                $newData = substr($newData, 0, -StreamHelper::MAC_SIZE); 
            }
            $expectedMac = StreamHelper::generateMac($this->keys['iv'] . $newData, $this->keys['macKey']);
            // при чтении стрима по частям мы не можем его валидировать, так как для валидации нужет ВЕСЬ файл
            // так что валидация сработает только если ВЕСЬ файл попадает в один блок стрима при кодировании и раскодировании
            if (!hash_equals($mac, $expectedMac)) {
                throw new RuntimeException('DecryptionStream not valid');
            }
            $padding = 0;
        }

        if(strlen($newData) >= StreamHelper::BLOCK_SIZE) {
            $decrypted = openssl_decrypt(
                $newData,
                'aes-256-cbc',
                $this->keys['cipherKey'],
                OPENSSL_RAW_DATA | $padding,
                $this->curIv
            );
     
            $this->decryptedData .= $decrypted;
            $this->curIv = substr($newData, -StreamHelper::BLOCK_SIZE);
        }
    
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
