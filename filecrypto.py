import random
import os
import hashlib


class CRYPTO(object):

    def __init__(self, plaintext_bytes):
        self.plaintext_bytes_len = len(plaintext_bytes)
        self.plaintext_int = int(plaintext_bytes.hex(), base=16)
        # なぜか最後の文字を乱数の範囲に含む

    def get_cryptogram(self, password):
        key = self._generate_key_int(self.plaintext_bytes_len, password)
        return self._get_bytes_from_int(self.plaintext_int ^ key, self.plaintext_bytes_len)

    @staticmethod
    def _generate_key_int(plaintext_bytes_len, password):
        seed = int(hashlib.sha256(str(password).encode()).hexdigest(), base=16)
        random.seed(seed)
        key_int = random.randint(0, 256 ** plaintext_bytes_len - 1)
        return key_int

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

    def get_cryptogram(self, password):
        with open(self.filename+'.enc', 'bw') as ew:
            ew.write(super().get_cryptogram(password))

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
    # FILENAME = 'files/newtest.txt'
    # f = CRYPTO_FILE(FILENAME)
    # f.get_cryptogram('DINNER')
    # CRYPTO_FILE.decrypt(FILENAME+'.enc', 'DINNER', underscore=True)

    s = CRYPTO('やぶれかぶれのヤブ医者が\n竹薮の中で擦ったコラさ'.encode())
    cr = s.get_cryptogram('寿司')
    an = f'{int(cr.hex(), base=16):b}'
    print('暗号文', an, len(an))
    key_int = s._generate_key_int(len('やぶれかぶれのヤブ医者が\n竹薮の中で擦ったコラさ'.encode()), '寿司')
    hi = f'{key_int:0560b}'
    print('秘密鍵', hi, len(hi))
    raw = 'やぶれかぶれのヤブ医者が\n竹薮の中で擦ったコラさ'.encode().hex()
    ge= f'{int(raw, base=16):b}'
    print('原　文', ge, len(ge))

    # dec = CRYPTO.decrypt(cr, '寿司')
    # print(dec.decode(errors='replace'))
