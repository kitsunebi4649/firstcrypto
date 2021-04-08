import random
import os
import hashlib


class CRYPTO(object):

    def __init__(self, plaintext_bytes):
        self._plaintext_bytes_len = len(plaintext_bytes)
        self._plaintext_int = int(plaintext_bytes.hex(), base=16)
        # なぜか最後の文字を乱数の範囲に含む

    def encrypt(self, password):
        key = self._generate_key_int(self._plaintext_bytes_len, password)
        return self._get_bytes_from_int(self._plaintext_int ^ key, self._plaintext_bytes_len)

    @staticmethod
    def _generate_key_int(plaintext_bytes_len, password):
        seed = int(hashlib.sha256(str(password).encode()).hexdigest(), base=16)
        random.seed(seed)
        return random.randint(0, 256 ** plaintext_bytes_len - 1)

    @staticmethod
    def _get_bytes_from_int(num, total_bytes_len):  # total_lenは数値を指定しないとbyte変換エラーが起こる
        total_bytes_hex_len = total_bytes_len * 2  # 1byte = 2 * 16進数なので
        return bytes.fromhex(f'{num:0{total_bytes_hex_len}x}')

    @staticmethod
    def decrypt(cryptogram_bytes, password):
        decrypt_int = int(cryptogram_bytes.hex(), base=16) ^ CRYPTO._generate_key_int(len(cryptogram_bytes), password)
        return CRYPTO._get_bytes_from_int(decrypt_int, len(cryptogram_bytes))


class CRYPTO_FILE(CRYPTO):

    def __init__(self, filename):
        self.filename = filename
        with open(filename, 'br') as fr:
            file_bytes = fr.read()
        super().__init__(file_bytes)

    def encrypt(self, password):
        with open(self.filename+'.enc', 'bw') as ew:
            ew.write(super().encrypt(password))

    @staticmethod
    def decrypt(encrypted_file_path, password, underscore=False):
        with open(encrypted_file_path, 'br') as er:
            encrypted_data = er.read()

        original_filename = os.path.splitext(encrypted_file_path)[0]
        if underscore:
            original_filename = os.path.split(original_filename)[0] + '/_' + os.path.split(original_filename)[1]

        with open(original_filename, 'bw') as fw:
            fw.write(CRYPTO.decrypt(encrypted_data, password))


if __name__ == '__main__':
    # file = CRYPTO_FILE('files/Monero_Promo.m4v')
    # file.encrypt('bdibda')
    CRYPTO_FILE.decrypt('files/Monero_Promo.m4v.enc', 'bdibda', True)
