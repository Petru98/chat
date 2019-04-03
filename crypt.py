"""
Libraries:
    base64
    Crypto / cryptodome
"""

import base64
import Crypto.Random
import Crypto.Cipher.AES
import Crypto.Hash.SHA256
import Crypto.PublicKey.RSA
import Crypto.Cipher.PKCS1_OAEP

class AES256():
    @staticmethod
    def encrypt(data, key, to_binary = False):
        assert(isinstance(data, (bytearray, bytes)))
        assert(isinstance(key, (bytearray, bytes)))

        # preprocess
        padding = 32 - len(data) % 32
        data += padding * chr(padding).encode()

        # initialization
        key = Crypto.Hash.SHA256.new(key).digest()

        iv = Crypto.Random.get_random_bytes(Crypto.Cipher.AES.block_size)
        cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv)

        # encrypt
        data = iv + cipher.encrypt(data)

        # postprocess
        if(to_binary == False):
            data = base64.b64encode(data)

        return data

    @staticmethod
    def decrypt(data, key, from_binary = False):
        assert(isinstance(data, (bytearray, bytes)))
        assert(isinstance(key, (bytearray, bytes)))

        # preprocess
        if(from_binary == False):
            data = base64.b64decode(data)

        # initialization
        key = Crypto.Hash.SHA256.new(key).digest()

        iv = data[ : Crypto.Cipher.AES.block_size]
        cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv)

        # decrypt
        data = cipher.decrypt(data[Crypto.Cipher.AES.block_size : ])

        # postprocess
        data = data[ : -data[-1]]

        return data


class RSA():
    from Crypto.PublicKey.RSA import RsaKey
    Key = RsaKey

    class Cipher(Crypto.Cipher.PKCS1_OAEP.PKCS1OAEP_Cipher):
        def __init__(self, key = None, hashAlgo = Crypto.Hash.SHA256, mgfunc = Crypto.Cipher.PKCS1_OAEP.MGF1, label = "", randfunc = None):
            return super().__init__(key, hashAlgo = hashAlgo, mgfunc = mgfunc, label = label, randfunc = randfunc)

        def publickey(self):
            return RSA.Cipher(self._key.publickey(), self._hashObj, self._mgf, self._label, self._randfunc)

        def exportKey(self, *args, **kwargs):
            return self._key.exportKey(*args, **kwargs)

        def importKey(self, key, passphrase = None):
            self._key = Crypto.PublicKey.RSA.importKey(key, passphrase)
            return self

    @staticmethod
    def generateKey(bits, randfunc = None, e = 65537):
        return Crypto.PublicKey.RSA.generate(bits, randfunc, e)
    
    @staticmethod
    def createCipherFromKey(key, *args, **kwargs):
        return RSA.Cipher(key, *args, **kwargs)

    @staticmethod
    def createCipherFromExportedKey(key, passphrase = None, *args, **kwargs):
        return RSA.Cipher(Crypto.PublicKey.RSA.importKey(key, passphrase), *args, **kwargs)

    @staticmethod
    def generateCipher(bits, randfunc = None, e = 65537, *args, **kwargs):
        return RSA.Cipher(RSA.generateKey(bits, randfunc, e), *args, **kwargs)

    @staticmethod
    def encrypt(data, key):
        # preprocess
        try:
            data = data.encode()
        except AttributeError:
            pass

        # initialization
        result = b""
        chunk_size = 0
        try:
            chunk_size = key._key.size_in_bytes()
        except AttributeError:
            chunk_size = key.size_in_bytes()
            key = createCipherFromKey(key)
        chunk_size -= 2 + 2*key._hashObj.digest_size

        # encrypt
        while len(data) > 0:
            chunk = data[0 : chunk_size]
            data = data[chunk_size :]

            result += key.encrypt(chunk)

        return result

    @staticmethod
    def decrypt(data, key):
        # preprocess
        try:
            data = data.encode()
        except AttributeError:
            pass

        # initialization
        result = b""
        chunk_size = 0
        try:
            chunk_size = key._key.size_in_bytes()
        except AttributeError:
            chunk_size = key.size_in_bytes()
            key = createCipherFromKey(key)

        # decrypt
        while len(data) > 0:
            chunk = data[0 : chunk_size]
            data = data[chunk_size :]

            result += key.decrypt(chunk)

        return result

#x = RSA.generateCipher(1024)
#print(RSA.decrypt(RSA.encrypt(b"12"*63, x), x).count(b"12"))
