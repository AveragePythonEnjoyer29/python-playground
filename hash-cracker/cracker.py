"""
This project is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, 
either version 3 of the License, or (at your option) any later version.

This project is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this code. 
If not, see <https://www.gnu.org/licenses/>. 
"""

import hashlib, argparse, os

parser = argparse.ArgumentParser()
parser.add_argument("--hash", help="hash to crack", default=None)
parser.add_argument("--algorithm", help="hashing algorithm (check --list-algorithms for more)", default=None)
parser.add_argument("--wordlist",  help="wordlist to use", default=None)
parser.add_argument("--list-algorithms", action="store_true", default=False)
args = parser.parse_args()

# all hashing algorithms
hashing_algorithms = {
    "md5": hashlib.md5,
    "blake2b": hashlib.blake2b,
    "blake2s": hashlib.blake2s,
    "sha1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
    "sha3_224": hashlib.sha3_224,
    "sha3_256": hashlib.sha3_256,
    "sha3_384": hashlib.sha3_384,
    "sha3_512": hashlib.sha3_512,
}

wordlist = []

def cracker() -> None:
    """
    Simple `for` loop that cracks @args.hash

    :returns None: Nothing
    """

    h = hashing_algorithms[args.algorithm]

    for i, line in enumerate(wordlist, 1):
        digest = h(line.encode()).hexdigest()

        if digest == args.hash:
            print(f"\n\n[!] Hash broken [!]\nHash: {digest}\nText: {line}\nIteration: {i}\n\n")
            
            break

if __name__ == "__main__":

    if args.list_algorithms:
        print(f"Supported hashing algorithms: {', '.join(hashing_algorithms.keys())}")
        exit(0)

    if not args.hash:
        print("No hash supplied!")
        exit(1)
    
    if not args.algorithm:
        print("No hashing algorithm supplied!")
        exit(1)

    args.algorithm = args.algorithm.lower() if args.algorithm else args.algorithm

    if not args.algorithm in hashlib.algorithms_available \
        or not args.algorithm in hashing_algorithms.keys():
            print("Hashing algorithm not supported!")
            exit(1)
    
    if not args.wordlist:
        print("No wordlist supplied!")
        exit(1)
    
    if not os.path.exists(args.wordlist):
        print("Wordlist not found!")
        exit(1)
    
    with open(args.wordlist) as fd:
        for line in fd.read().split("\n"):
            l = line.rstrip()

            if not l \
                or len(l) == 0 \
                or l.startswith("#"):
                continue

            wordlist.append(l)
    
    cracker()