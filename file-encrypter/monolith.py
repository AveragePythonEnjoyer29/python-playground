"""
This project is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, 
either version 3 of the License, or (at your option) any later version.

This project is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this code. 
If not, see <https://www.gnu.org/licenses/>. 
"""

import sys, argparse, os, shutil

from os.path import exists

from src.util import *
from src.hashers import *
from src.ciphers import *

parser = argparse.ArgumentParser()
parser.add_argument("--file", nargs=argparse.ONE_OR_MORE, help="file to encrypt", default=None)
parser.add_argument("--cipher", help="cipher to use when encrypting, see \"--list-ciphers\"", default="aes")
parser.add_argument("--hash-algo", help="hashing algorithm, see \"--list-hashing-algorithms\"", default="sha256")
parser.add_argument("--passphrase", help="passphrase to use when encrypting the file, defaults to random", default=None, nargs=argparse.ONE_OR_MORE)
parser.add_argument("--encrypt", action="store_true", default=False, help="encrypt the file")
parser.add_argument("--decrypt", action="store_true", default=False, help="decrypt the file")
parser.add_argument("--scramble-name", action="store_true", default=False, help="scramble file name")
parser.add_argument("--list-ciphers", action="store_true", default=False, help="list all ciphers")
parser.add_argument("--list-hashers", action="store_true", default=False, help="list all hashing algorithms")
args = parser.parse_args()

if args.list_ciphers:
    for cipher, info in cipherdict.items():
        print(f"{cipher} - {info['name']}")
        
    exit(0)

if args.list_hashers:
    for algo, info in hashdict.items():
        print(f"{algo} - {info['name']}")

    exit(0)

if not args.file:
    print("Please specify a file!")
    sys.exit(1)

args.file = " ".join(args.file)

if not exists(args.file):
    print("File not found!")
    sys.exit(1)

if not args.encrypt and not args.decrypt:
    args.encrypt = True

if not args.passphrase:
    args.passphrase = randomstr(24)
else:
    args.passphrase = " ".join(args.passphrase)

def chunkify(file_obj):
    while 1:
        data = file_obj.read(4096)
        if not data:
            break

        yield data

if __name__ == "__main__":

    cipher_info = cipherdict.get(args.cipher)
    if not cipher_info:
        print("Invalid cipher selected!")
        sys.exit(1)
    
    b_passphrase = stretch_key(
        args.passphrase.encode(),
        cipher_info["key_size"]
    )
    
    if len(b_passphrase) != cipher_info["key_size"]:
        print(f"Invalid key size, must be {cipher_info['key_size']}!")
        sys.exit(1)
    
    hasher = hashdict.get(args.hash_algo)
    if not hasher:
        print("Invalid hashing algorithm selected!")
        sys.exit(1)
    
    hashfunction = hasher["function"]
    
    cipher = cipher_info["cipher"]
    nonce_size = cipher_info["nonce_size"]
    
    if not exists("temp"):
        os.mkdir("temp")

    tmpdir = join("temp", randomstr(12))

    if args.encrypt:

        outfile = args.file
        if args.scramble_name:
            outfile = randomstr(24)

        nonce = os.urandom(nonce_size)
        cipher = cipher(
            b_passphrase,
            nonce
        )

        buffer = b""
        with open(args.file, "rb") as fd:
            for chunk in chunkify(fd):
                buffer += chunk
        
        enc_file = join(tmpdir, outfile)
        metadata_file = join(tmpdir, "metadata.json")

        os.mkdir(tmpdir)

        encrypted_buffer = cipher.encrypt(buffer)

        # calculate hash digest
        digest = hashfunction(encrypted_buffer)

        # write encrypted file
        with open(enc_file, "wb") as fd:
            fd.write(encrypted_buffer)

        # write metadata file
        put_metadata(metadata_file, {
            "name": outfile,
            "cipher": args.cipher,
            "nonce": nonce,
            "hash": {
                "digest": digest
            }
        })

        # create zip file with the files
        zip_file = f"{randomstr(6)}.mono"
        z = pack_file(zip_file, [
            metadata_file,
            enc_file
        ])

        z.close()

        print(f"Encrypted file: {zip_file}")
        
    elif args.decrypt:

        tmp = unpack_file(args.file)
        if not tmp:
            print("Failed to unpack!")
            sys.exit(1)

        metadata = get_metadata(tmp)
        
        cipher = cipher(
            b_passphrase,
            metadata["nonce"]
        )

        outfile = metadata["name"]

        buffer = b""
        with open(join(tmp, outfile), "rb") as fd:
            for chunk in chunkify(fd):
                buffer += chunk

        # verify hash
        digest = hashfunction(buffer)
        if digest != metadata["hash"]["digest"]:
            print("Hash does not match!")
            exit(1)

        # then decrypt
        decrypted_buffer = cipher.decrypt(buffer)
        
        with open(outfile, "wb") as fd:
            fd.write(decrypted_buffer)

        print(f"Decrypted file: {outfile}")
    
    if exists("temp"):
        shutil.rmtree("temp")