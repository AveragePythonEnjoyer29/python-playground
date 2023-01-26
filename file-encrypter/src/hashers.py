"""
This project is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, 
either version 3 of the License, or (at your option) any later version.

This project is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this code. 
If not, see <https://www.gnu.org/licenses/>. 
"""

import hashlib
from Crypto.Hash import KangarooTwelve, SHA3_512, BLAKE2b, BLAKE2s, SHAKE128, SHAKE256
from skein import skein1024

def sha256(text: bytes) -> str:
    return hashlib.sha256(text).hexdigest()

def sha512(text: bytes) -> str:
    return hashlib.sha512(text).hexdigest()

def sha3_512(text: bytes) -> str:
    sha3 = SHA3_512.new()
    sha3.update(text)

    return sha3.hexdigest()

def kangarooTwelve(text: bytes) -> str:
    k12 = KangarooTwelve.new()

    for chunk in range(0, len(text), 8192):
        k12.update(text[chunk:chunk+8192])
    
    return k12.read(128).hex()

def blake2s(text: bytes) -> str:
    blake = BLAKE2s.new()
    blake.update(text)

    return blake.hexdigest()

def blake2b(text: bytes) -> str:
    blake = BLAKE2b.new()
    blake.update(text)

    return blake.hexdigest()

def shake128(text: bytes) -> str:
    shake = SHAKE128.new()
    shake.update(text)

    return shake.read(128).hex()

def shake256(text: bytes) -> str:
    shake = SHAKE256.new()
    shake.update(text)

    return shake.read(256).hex()

def skein_1024(text: bytes) -> str:

    return skein1024(
        text, 
        digest_bits=1024
    ).hexdigest()

hashdict = {
    "sha256": {
        "name": "SHA256",
        "function": sha256,
        "size": 64
    },

    "sha512": {
        "name": "SHA512",
        "function": sha512,
        "size": 128
    },

    "sha3_512": {
        "name": "SHA3/512",
        "function": sha3_512,
        "size": 128
    },

    "k12": {
        "name": "KangarooTwelve",
        "function": kangarooTwelve,
        "size": 128
    },

    "blake2s": {
        "name": "BLAKE2s (best on 32 bit)",
        "function": blake2s,
        "size": 64
    },

    "blake2b": {
        "name": "BLAKE2b (best on 64 bit)",
        "function": blake2b,
        "size": 128
    },

    "shake128": {
        "name": "SHAKE128",
        "function": shake128,
        "size": 256
    },

    "shake256": {
        "name": "SHAKE256",
        "function": shake256,
        "size": 512
    },

    "skein1024": {
        "name": "Skein-1024",
        "function": skein_1024,
        "size": 256
    }
}