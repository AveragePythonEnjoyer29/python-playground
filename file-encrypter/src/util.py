"""
This project is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, 
either version 3 of the License, or (at your option) any later version.

This project is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this code. 
If not, see <https://www.gnu.org/licenses/>. 
"""

import zipfile, json

from random import choices
from os.path import exists, join, isdir, isfile
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from base64 import urlsafe_b64encode, urlsafe_b64decode

def stretch(
    source: bytes,
    length: int
    ) -> bytes:
    """
    Stretches the bytes from @source using maths to @length

    :param source bytes: Bytes to stretch
    :param length int: Final length
    """

    return HKDF(
        algorithm=hashes.SHA512(),
        length=length,
        salt=None,
        info=None,
    ).derive(source)

def randomstr(
    length: int,
    chars: str | list[str] = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM"
    ) -> str:
    """
    Generates a @length characters long random string

    :param length int: Length of the character
    :param chars str or list[str]: List of allowed characters
    :returns str: Random string
    """

    return "".join(choices(chars, k=length))

def unpack_file(
    filename: str
    ) -> str | None:
    """
    Unpacks an encrypted .mono file

    :param filename str: Name of the file
    :returns str or None: Unpacked directory name, None if errors occurred
    """

    if not exists(filename):
        return None

    tmp = randomstr(6)
    tmp_path = join("temp", tmp)

    try:
        with zipfile.ZipFile(filename, "r") as zip_ref:
            zip_ref.extractall(tmp_path)

    except Exception:
        return None
    
    return tmp_path

def pack_file(
    filename: str,
    files: list[str]
    ) -> zipfile.ZipFile:
    """
    Packs @files in a zipfile with the name @filename

    :param filename str: Destination filename
    :param files list[str]: List of files to be included in the zipfile
    :returns zipfile.ZipFile: A ZipFile object
    """

    zip_ref = zipfile.ZipFile(filename, "w")
        
    for file in files:
        if not exists(file):
            continue

        arcname = file.split("/")[-1] # get file name

        zip_ref.write(file, arcname=arcname)
    
    return zip_ref

def put_metadata(
    fileOrDir: str,
    raw: dict
    ) -> bool:
    """
    Stores the metadata from @raw in @fileOrDir

    :param fileOrDir str: File or Directory to store metadata in
    :param raw dict: Unparsed metadata
    :returns bool: True if no errors occurred, False if otherwise
    """

    if isdir(fileOrDir):
        metadata_file = join(fileOrDir, "metadata.json")
    
    else:
        metadata_file = fileOrDir
    
    metadata = {
        "name": raw["name"],
        "nonce": urlsafe_b64encode(raw["nonce"]).decode(),
        "hash": {
            "digest": raw["hash"]["digest"]
        }
    }
    
    with open(metadata_file, "w") as fd:
        fd.write(json.dumps(
            metadata, 
            indent=4
        ))
    
    return True

def get_metadata(
    fileOrDir: str
    ) -> dict:
    """
    Parses Monolith metadata from @fileOrDir

    :param fileOrDir str: File or Directory to parse metadata from
    :returns dict: Dictionary containing all metadata
    """

    if isfile(fileOrDir):

        tmp = unpack_file(fileOrDir)
        if not tmp:
            return {}

    else:
        tmp = fileOrDir

    try:

        with open(join(tmp, "metadata.json")) as fd:
            raw = json.loads(fd.read())

    except Exception:
        raw = None
    
    if not raw:
        return {}
    
    metadata = {
        "name": raw["name"],
        "nonce": urlsafe_b64decode(raw["nonce"]),
        "hash": {
            "digest": raw["hash"]["digest"]
        }
    }

    return metadata