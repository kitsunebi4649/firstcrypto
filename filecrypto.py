import random
import os
import hashlib


class Crypto(object):

    def __init__(self, plaintext_bytes):
        self._plaintext_bytes_len = len(plaintext_bytes)
        self._plaintext_int = int(plaintext_bytes.hex(), base=16)  # なぜか最後の文字を乱数の範囲に含む

    def encrypt(self, password):
        key = self._generate_key_int(self._plaintext_bytes_len, password)
        return self._get_bytes_from_int(self._plaintext_int ^ key, self._plaintext_bytes_len)

    @staticmethod
    def _generate_key_int(plaintext_bytes_len, password):
        seed = int(hashlib.sha256(str(password).encode('utf-8')).hexdigest(), base=16)
        random.seed(seed)
        return random.randint(0, 256 ** plaintext_bytes_len - 1)

    @staticmethod
    def _get_bytes_from_int(num, total_bytes_len):  # total_lenは数値を指定しないとbyte変換エラーが起こる
        total_bytes_hex_len = total_bytes_len * 2  # 1byte = 2 * 16進数なので
        return bytes.fromhex(f'{num:0{total_bytes_hex_len}x}')

    @staticmethod
    def decrypt(cryptogram_bytes, password):
        decrypt_int = int(cryptogram_bytes.hex(), base=16) ^ Crypto._generate_key_int(len(cryptogram_bytes), password)
        return Crypto._get_bytes_from_int(decrypt_int, len(cryptogram_bytes))


class File_Crypto(Crypto):

    def __init__(self, filename):
        with open(filename, 'br') as fr:
            file_bytes = fr.read()
        self.version = bytes.fromhex('01')
        self.checksum = hashlib.sha256(file_bytes).digest()
        self.filepath = filename
        super().__init__(file_bytes)

    def encrypt(self, password):
        filename_bytes = os.path.split(self.filepath)[1].encode('utf-8')
        filename_len = bytes.fromhex(f'{len(filename_bytes):04x}')
        new_filename = os.path.splitext(self.filepath)[0] + '.enc'
        with open(new_filename, 'bw') as ew:  # TODO  ファイル名もソルトもファイル内に保持
            ew.write(self.version + self.checksum + filename_len + filename_bytes + super().encrypt(password))

    @staticmethod
    def decrypt(encrypted_file_path, password):
        with open(encrypted_file_path, 'br') as er:
            version = er.read(1)
            checksum = er.read(32)
            filename_len = int(er.read(2).hex(), base=16)
            filename = er.read(filename_len).decode('utf-8')
            decrypted_data = Crypto.decrypt(er.read(), password)

        if version != bytes.fromhex('01'):
            raise Exception('version error')
        if checksum != hashlib.sha256(decrypted_data).digest():
            raise ValueError('wrong password')

        new_filepath = os.path.split(encrypted_file_path)[0] + '/' + filename

        with open(new_filepath, 'bw') as fw:
            fw.write(decrypted_data)


if __name__ == '__main__':
    file = File_Crypto('Promo (1).m4v')
    file.encrypt('1234abc')
    File_Crypto.decrypt('files/Promo (1).enc', '1234abc')
