import random
import os
import hashlib


class CRYPTO(object):

    def __init__(self, plaintext_bytes, key_int=None):
        self.plaintext_bytes_len = len(plaintext_bytes)
        self.plaintext_int = int(plaintext_bytes.hex(), base=16)
        self.key = key_int if key_int else random.randint(0, 256 ** self.plaintext_bytes_len - 1)
        # なぜか最後の文字を乱数の範囲に含む

    def get_cryptogram(self):
        return self._get_bytes_from_int(self.plaintext_int ^ self.key, self.plaintext_bytes_len)

    def get_key(self):
        return self._get_bytes_from_int(self.key, self.plaintext_bytes_len)

    @staticmethod
    def _get_bytes_from_int(num, total_bytes_len):  # total_lenは数値を指定しないとbyte変換エラーが起こる
        total_bytes_hex_len = total_bytes_len * 2  # 1byte = 2 * 16進数なので
        return bytes.fromhex(f'{num:0{total_bytes_hex_len}x}')

    @staticmethod
    def decrypt(cryptogram_bytes, key_bytes):
        decrypt_int = int(cryptogram_bytes.hex(), base=16) ^ int(key_bytes.hex(), base=16)
        return CRYPTO._get_bytes_from_int(decrypt_int, len(cryptogram_bytes))


class CRYPTO_FILE(CRYPTO):

    def __init__(self, filename):
        self.filename = filename
        with open(filename, 'br') as fr:
            file_bytes = fr.read()
        super().__init__(file_bytes)

    def get_cryptogram(self):
        with open(self.filename+'.en', 'bw') as ew:
            ew.write(super().get_cryptogram())

    def get_key(self):
        with open(self.filename+'.kk', 'bw') as kw:
            kw.write(super().get_key())

    @staticmethod
    def decrypt(encrypted_file_path, key_file_path, underscore=False):
        with open(encrypted_file_path, 'br') as er:
            encrypted_data = er.read()
        with open(key_file_path, 'br') as kr:
            key_data = kr.read()

        original_filename = os.path.splitext(encrypted_file_path)[0]
        if underscore:
            original_filename = os.path.split(original_filename)[0] + '/_' + os.path.split(original_filename)[1]

        with open(original_filename, 'bw') as fw:
            fw.write(CRYPTO.decrypt(encrypted_data, key_data))


class CRYPTO_SHORT_KEY(CRYPTO):

    def __init__(self, plaintext_bytes, password):
        super().__init__(plaintext_bytes, self.generate_key_int(plaintext_bytes, password))

    @staticmethod
    def generate_key_int(plaintext_bytes, password):
        seed = int(hashlib.sha256(str(password).encode()).hexdigest(), base=16)
        random.seed(seed)
        key_int = random.randint(0, 256 ** len(plaintext_bytes) - 1)
        return key_int

    @staticmethod
    def decrypt(cryptogram_bytes, password):
        key_int = CRYPTO_SHORT_KEY.generate_key_int(cryptogram_bytes, password)
        key_bytes = CRYPTO._get_bytes_from_int(key_int, len(cryptogram_bytes))
        return CRYPTO.decrypt(cryptogram_bytes, key_bytes)


if __name__ == '__main__':
    # FILENAME = 'files/image01.gif'
    # f = CRYPTO_FILE(FILENAME)
    # f.get_key()
    # f.get_cryptogram()
    # CRYPTO_FILE.decrypt(FILENAME+'.en', FILENAME+'.kk', underscore=True)

    s = CRYPTO_SHORT_KEY('やぶれかぶれのヤブ医者が\n竹薮の中で擦ったコラさ'.encode(), 'MONERO')
    cr = s.get_cryptogram()
    print(cr.decode(errors='replace'))

    dec = CRYPTO_SHORT_KEY.decrypt(cr, 'MONERO')
    print(dec.decode(errors='replace'))
