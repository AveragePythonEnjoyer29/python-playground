"""
This project is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, 
either version 3 of the License, or (at your option) any later version.

This project is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this code. 
If not, see <https://www.gnu.org/licenses/>. 
"""

from cryptography.fernet import Fernet
from Crypto.Cipher import ChaCha20_Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from skein import threefish

from base64 import urlsafe_b64encode

from src.util import *
from src.serpent import *

# DO NOT USE
# HAS NOT BEEN VERIFIED
# TO BE A SECURE IMPLEMENTATION
# YET!!!!!
class Serpent_Cipher:
    def __init__(
        self,
        key: bytes,
        nonce: bytes
        ) -> None:

        key_hex = key.hex()
        b_key = convert2bitstring(
            key_hex, 
            len(key_hex) * 4
        )

        self.key = pad(b_key)
        self.nonce = nonce
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Takes @plaintext and encrypts it using `Serpent(plaintext)`

        :param plaintext bytes: Text to encrypt
        :returns bytes: Encrypted ciphertext
        """

        blocks = [
            plaintext[i:i+16] 
            for i in range(0, len(plaintext), 16)
        ]

        if len(blocks[-1]) < 16:
            blocks[-1] += b' ' * (16 - len(blocks[-1]))
        
        ciphertext = b''.join([
            encrypt(block, self.key) 
            for block in blocks
        ])

        return ciphertext
    
    def decrypt(
        self, 
        ciphertext: bytes
        ) -> bytes | None:
        """
        Takes @ciphertext and encrypts it using `Serpent(ciphertext)`

        :param ciphertext bytes: Text to decrypt
        :returns bytes or None: Encrypted ciphertext, None if any errors occurred
        """

        cipher_blocks = [
            ciphertext[i:i+32] 
            for i in range(0, len(ciphertext), 32)
        ]

        plaintext = b''.join([
            decrypt(block, self.key) 
            for block in cipher_blocks
        ]).strip()

        return plaintext

# TODO: 
# move from ECB to something more secure
class Threefish_Cipher:
    def __init__(
        self,
        key: bytes,
        tweak: bytes
        ) -> None:

        self.key = key
        self.tweak = tweak

        self.cipher = threefish(
            key, 
            tweak
        )
    
    def encrypt(
        self,
        cleartext: bytes
        ) -> bytes:
        """
        Takes @plaintext and encrypts it using `Threefish(plaintext))`

        :param plaintext bytes: Text to encrypt
        :returns bytes: Encrypted ciphertext
        """

        chunked = [
            cleartext[i:i+len(self.key)] 
            for i in range(0, len(cleartext), len(self.key))
        ]

        if len(chunked[-1]) != len(self.key):
            chunked[-1] += b" " * (len(self.key) - len(chunked[-1]))

        ciphertext = []
        for chunk in chunked:

            # encrypt chunk            
            ciphertext.append(
                self.cipher.encrypt_block(chunk)
            )

        return b"".join(ciphertext)
    
    def decrypt(
        self,
        ciphertext: bytes
        ) -> bytes | None:
        """
        Takes @ciphertext and encrypts it using `Threefish(ciphertext)`

        :param ciphertext bytes: Text to decrypt
        :returns bytes or None: Encrypted ciphertext, None if any errors occurred
        """

        try:
            chunked = [
                ciphertext[i:i+len(self.key)] 
                for i in range(0, len(ciphertext), len(self.key))
            ]

            cleartext = []
            for chunk in chunked:

                cleartext.append(
                    self.cipher.decrypt_block(chunk)
                )
            
            cleartext = b"".join(cleartext).strip()

        except Exception:
            cleartext = None
        
        return cleartext

class TripleAes_Cipher:
    def __init__(
        self,
        key: bytes,
        iv: bytes
        ) -> None:

        self.key = key
        self.iv = iv

        self.keys = [] # holds the 3 keys
        for _key in range(0, len(self.key), 32):
            self.keys.append(
                self.key[_key:_key+32]
            )
        
        self.ivs = [] # holds the 3 ivs
        for _iv in range(0, len(self.iv), 16):
            self.ivs.append(
                self.iv[_iv:_iv+16]
            )
        
        self.ciphers = []
        for i in range(3):
            cipher = Aes_Cipher(
                self.keys[i],
                self.ivs[i]
            )

            self.ciphers.append(cipher)
        
    def encrypt(
        self,
        plaintext: bytes
        ) -> bytes:
        """
        Takes @plaintext and encrypts it using `AES(AES(AES(plaintext)))`

        :param plaintext bytes: Text to encrypt
        :returns bytes: Encrypted ciphertext
        """

        ct = plaintext
        for cipher in self.ciphers:
            ct = cipher.encrypt(ct)

        return ct
    
    def decrypt(
        self,
        ciphertext: bytes
        ) -> bytes | None:
        """
        Takes @ciphertext and encrypts it using `AES(AES(AES(ciphertext)))`

        :param ciphertext bytes: Text to decrypt
        :returns bytes or None: Encrypted ciphertext, None if any errors occurred
        """

        try:
            cleartext = ciphertext
            for cipher in self.ciphers:
                cleartext = cipher.decrypt(cleartext)

        except Exception:
            cleartext = None
        
        return cleartext

class Aes_XChaCha20Poly1305_Cipher:
    def __init__(
        self,
        key: bytes,
        nonce: bytes
        ) -> None:

        self.key = key
        self.nonce = nonce

        self.stretched_key = stretch_key(
            key, 
            64 # AES and Camellia
        )

        self.stretched_nonce = stretch_key(
            nonce,
            40
        )

        self.aes_key = self.stretched_key[0:32]
        self.xchacha_key = self.stretched_key[32:64]

        self.aes_iv = self.stretched_nonce[0:16]
        self.xchacha_nonce = self.stretched_nonce[16:]

        self.cipher_aes = Aes_Cipher(
            self.aes_key,
            self.aes_iv
        )

        self.cipher_xchacha = XChaCha20Poly1305_Cipher(
            self.xchacha_key,
            self.xchacha_nonce
        )

    def encrypt(
        self,
        plaintext: bytes
        ) -> bytes:
        """
        Takes @plaintext and encrypts it using `XChaCha20Poly1305(AES(plaintext))`

        :param plaintext bytes: Text to encrypt
        :returns bytes: Encrypted ciphertext
        """

        ciphertext_1 = self.cipher_aes.encrypt(plaintext)
        ciphertext_final = self.cipher_xchacha.encrypt(ciphertext_1)

        return ciphertext_final
    
    def decrypt(
        self,
        ciphertext: bytes
        ) -> bytes | None:
        """
        Takes @ciphertext and encrypts it using `AES(XChaCha20Poly1305(ciphertext))`

        :param ciphertext bytes: Text to decrypt
        :returns bytes or None: Encrypted ciphertext, None if any errors occurred
        """

        plaintext_1 = self.cipher_aes.decrypt(ciphertext)
        if not plaintext_1:
            return b""

        plaintext_final = self.cipher_xchacha.decrypt(plaintext_1)
        if not plaintext_final:
            plaintext_final = b""

        return plaintext_final

class Fernet_Cipher:
    def __init__(
        self,
        key: bytes,
        nonce: bytes
        ) -> None:

        self.key = urlsafe_b64encode(key).decode()
        self.nonce = nonce
    
    def encrypt(
        self,
        plaintext: bytes
        ) -> bytes:
        """
        Takes @plaintext and encrypts it using `Fernet(plaintext)`

        :param plaintext bytes: Text to encrypt
        :returns bytes: Encrypted ciphertext
        """

        fernet = Fernet(
            self.key
        )

        return fernet.encrypt(plaintext)

    def decrypt(
        self,
        ciphertext: bytes
        ) -> bytes | None:
        """
        Takes @ciphertext and decrypts it using `Fernet(ciphertext)`

        :param plaintext bytes: Text to encrypt
        :returns bytes or None: Encrypted ciphertext, None if any errors occurred
        """

        fernet = Fernet(
            self.key
        )

        try:
            cleartext = fernet.decrypt(ciphertext)
        except Exception:
            cleartext = None
        
        return cleartext

class XChaCha20Poly1305_Cipher:
    def __init__(
        self,
        key: bytes,
        nonce: bytes
        ) -> None:

        self.key = key
        self.nonce = nonce
    
    def encrypt(
        self,
        plaintext: bytes
        ) -> bytes:
        """
        Takes @plaintext and encrypts it using `XChaCha20Poly1305(plaintext)`

        :param plaintext bytes: Text to encrypt
        :returns bytes: Encrypted ciphertext
        """

        chacha = ChaCha20_Poly1305.new(
            key=self.key,
            nonce=self.nonce
        )

        ct, mac_tag = chacha.encrypt_and_digest(
            plaintext
        )

        return (mac_tag + self.nonce + ct)
    
    def decrypt(
        self,
        ciphertext: bytes
        ) -> bytes | None:
        """
        Takes @ciphertext and decrypts it using `XChaCha20Poly1305(ciphertext)`

        :param plaintext bytes: Text to encrypt
        :returns bytes or None: Encrypted ciphertext, None if any errors occurred
        """

        mac_tag = ciphertext[:16]
        nonce = ciphertext[16:40]
        ct = ciphertext[40:]

        chacha = ChaCha20_Poly1305.new(
            key=self.key,
            nonce=nonce
        )

        try:

            cleartext = chacha.decrypt_and_verify(
                ct,
                mac_tag
            )

        except Exception:
            cleartext = None

        return cleartext

class Aes_Camellia_Cipher:
    def __init__(
        self,
        key: bytes,
        iv: bytes
        ) -> None:

        self.key = key
        self.iv = iv

        self.stretched_key = stretch_key(
            key, 
            64 # AES and Camellia
        )

        self.aes_key = self.stretched_key[0:32]
        self.cam_key = self.stretched_key[32:64]

        self.cipher_aes = Cipher(
            algorithm=algorithms.AES(self.aes_key),
            mode=modes.CTR(iv)
        )

        self.cipher_camellia = Cipher(
            algorithm=algorithms.Camellia(self.cam_key),
            mode=modes.CTR(iv)
        )
    
    def encrypt(
        self,
        plaintext: bytes
        ) -> bytes:
        """
        Takes @plaintext and encrypts it using `AES(Camellia(plaintext))`

        :param plaintext bytes: Text to encrypt
        :returns bytes: Encrypted ciphertext
        """

        cam_enc = self.cipher_camellia.encryptor()

        ciphertext1 = cam_enc.update(plaintext) + cam_enc.finalize()

        aes_enc = self.cipher_aes.encryptor()
        ciphertext_final = aes_enc.update(ciphertext1) + aes_enc.finalize()

        return ciphertext_final
    
    def decrypt(
        self,
        ciphertext: bytes
        ) -> bytes | None:
        """
        Takes @ciphertext and decrypts it using `Camellia(AES(ciphertext))`

        :param plaintext bytes: Text to encrypt
        :returns bytes or None: Encrypted ciphertext, None if any errors occurred
        """

        try:

            aes_dec = self.cipher_aes.decryptor()
            cleartext1 = aes_dec.update(ciphertext) + aes_dec.finalize()

            cam_dec = self.cipher_camellia.decryptor()
            cleartext_final = cam_dec.update(cleartext1) + cam_dec.finalize()

        except Exception:
            cleartext_final = None

        return cleartext_final

class Aes_Cipher:
    def __init__(
        self,
        key: bytes,
        iv: bytes
        ) -> None:

        self.key = key
        self.iv = iv
        
        self.cipher = Cipher(
            algorithm=algorithms.AES(key),
            mode=modes.CTR(iv)
        )
    
    def encrypt(
        self,
        plaintext: bytes
        ) -> bytes:
        """
        Takes @plaintext and encrypts it using `AES256(plaintext)`

        :param plaintext bytes: Text to encrypt
        :returns bytes: Encrypted ciphertext
        """

        enc = self.cipher.encryptor()
        ct = enc.update(plaintext) + enc.finalize()

        return ct
    
    def decrypt(
        self,
        ciphertext: bytes
        ) -> bytes | None:
        """
        Takes @ciphertext and decrypts it using `AES256(ciphertext)`

        :param ciphertext bytes: Ciphertext to decrypt
        :returns bytes or None: Encrypted ciphertext, None if any errors occurred
        """

        try:
            
            dec = self.cipher.decryptor()
            ct = dec.update(ciphertext) + dec.finalize()

        except Exception:
            ct = None

        return ct

cipherdict = {
    "aes": {
        "name": "AES-256",
        "cipher": Aes_Cipher,
        "key_size": 32,
        "nonce_size": 16
    },

    "aes_camellia": {
        "name": "AES-256 + Camellia",
        "cipher": Aes_Camellia_Cipher,
        "key_size": 32,
        "nonce_size": 16
    },

    "xchacha": {
        "name": "XChaCha20Poly1305",
        "cipher": XChaCha20Poly1305_Cipher,
        "key_size": 32,
        "nonce_size": 24
    },

    "xchacha_aes": {
        "name": "XChaCha20Poly1305 + AES-256",
        "cipher": Aes_XChaCha20Poly1305_Cipher,
        "key_size": 32,
        "nonce_size": 16
    },

    "fernet": {
        "name": "Fernet",
        "cipher": Fernet_Cipher,
        "key_size": 32,
        "nonce_size": 0
    },

    "triple-aes": {
        "name": "Triple AES-256",
        "cipher": TripleAes_Cipher,
        "key_size": 96,
        "nonce_size": 48
    },

    # TODO: drop ECB for something more secure
    #"threefish": {
    #    "name": "Threefish",
    #    "cipher": Threefish_Cipher,
    #    "key_size": 128,
    #    "nonce_size": 16
    #}
}