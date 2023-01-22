"""
This project is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, 
either version 3 of the License, or (at your option) any later version.

This project is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this code. 
If not, see <https://www.gnu.org/licenses/>. 
"""

import hashlib, argparse, string

from random import choices
from base64 import b64encode, b64decode
from Crypto.Random import get_random_bytes
from Crypto.Cipher import ChaCha20_Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

parser = argparse.ArgumentParser()
parser.add_argument("message", nargs=argparse.ONE_OR_MORE, help="data to encrypt/decrypt")
parser.add_argument("--passphrase", help="passphrase to use when encrypting the message, defaults to random", default=None, nargs=argparse.ONE_OR_MORE)
parser.add_argument("--encrypt", action="store_true", default=False)
parser.add_argument("--decrypt", action="store_true", default=False)
args = parser.parse_args()

if not args.encrypt and not args.decrypt:
    args.encrypt = True

def hash_message(
    msg: str | bytes
    ) -> str:
    """
    Takes @msg and turns it into a SHA512 hash digest

    :param msg str: Message to hash
    :returns str: Hashdigest
    """

    if isinstance(msg, str):
        msg = msg.encode(
            "utf-8",
            errors="ignore"
        )

    return hashlib.sha512(msg).hexdigest()

def randomstr(
    len: int
    ) -> str:
    """
    Creates a random @len characters long string

    :param len int: Length of the string
    :returns str: Randomly generated string
    """

    return "".join(
        choices(
            string.ascii_letters, 
            k=len
        )
    )

def derive_key_from_passphrase(
    passphrase: str | bytes
    ) -> bytes:
    """
    Takes @passphrase and magically creates a new 32 bit key with it

    :param passphrase str or bytes: Passphrase to derive key from
    :returns bytes: Derived key
    """

    if isinstance(passphrase, str):
        passphrase = passphrase.encode(
            "utf-8",
            errors="ignore"
        )
    
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=None,
    ).derive(passphrase)

def encrypt():    
    key = derive_key_from_passphrase(args.passphrase)
    nonce = get_random_bytes(24) # XChaCha20 go brr
    
    cipher = ChaCha20_Poly1305.new(
        key=key, 
        nonce=nonce
    )

    b_msg = args.message.encode(
        "utf-8", 
        errors="ignore"
    )

    ciphertext, tag = cipher.encrypt_and_digest(b_msg)

    # prevents leaking content
    digest_salt = get_random_bytes(64).hex()
    digest = hash_message(args.message + digest_salt)

    final = [
        b64encode(ciphertext).decode(),
        b64encode(nonce).decode(),
        b64encode(tag).decode(),
        digest,
        digest_salt
    ]

    print("Result:")
    print(":".join(final))

def decrypt():
    key = derive_key_from_passphrase(args.passphrase)

    try:
        i = args.message.split(":")
        ciphertext = b64decode(i[0].encode())
        nonce = b64decode(i[1].encode())
        tag = b64decode(i[2].encode())
        digest = i[3]
        digest_salt = i[4]
    except Exception:
        print("Failed to parse data!")
        exit(1)

    cipher = ChaCha20_Poly1305.new(
        key=key,
        nonce=nonce
    )

    try:

        cleartext = cipher.decrypt_and_verify(
            ciphertext=ciphertext,
            received_mac_tag=tag
        ).decode()
    
    except Exception:
        print("Failed to decrypt ciphertext!")
        exit(1)

    if hash_message(cleartext + digest_salt) != digest:
        print("Hash does not match!")
        exit(1)

    print("Result:")
    print(cleartext)

if __name__ == "__main__":

    args.message = " ".join(args.message)

    if not args.passphrase:
        args.passphrase = randomstr(42) # default size
    else:
        args.passphrase = " ".join(args.passphrase)
    
    print(f"\nPassphrase used: {args.passphrase}")

    if args.encrypt:
        encrypt()
    else:
        decrypt()

    exit(0)