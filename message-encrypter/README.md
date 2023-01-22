# About
Simple message encrypter/decrypter using `XChaCha20Poly1305`, `SHA512` and `HKDF Key derivation`

# Usage
### Encrypting
```
>>> python3 encrypter.py your message --passphrase passphrase --encrypt
```

Example:
```
>>> python3 encrypter.py surprise attack, mcdonalds, tomorrow morning --passphrase omagawd --encrypt

Passphrase used: omagawd
Result:
DTDY8n5Dzt5fCEMuhGGfwHR02VhoMZ7WhdE4m0PqcbFqiQajc8Tt7RKhG88=:4yvi6VuR3HmByc7P/kdeTbM9va+oQHbB:ZkmDNhnmPMoKmG2VY/G1WA==:9bc6db54bc6789abc2efc2b65cf4716a694d56e4029b514af24a7e5d6d61bb6c9695469bb7bf7b9a08cc2496ed971de36a82cfe55592e9c6d5f6c91432bcda7f:b75b2ef87876df7910dcfec92b6b6330a51ea83567acbf07858893e905de95c92618bdaf63ad20cf6d49ee1b840742da8016008764febd0a0a302d1ea201654d
```

### Decrypting
Usage:
```
>>> python3 encrypter.py encrypted message --passphrase passphrase --decrypt
```

Example:
```
>>> python3 encrypter.py DTDY8n5Dzt5fCEMuhGGfwHR02VhoMZ7WhdE4m0PqcbFqiQajc8Tt7RKhG88=:4yvi6VuR3HmByc7P/kdeTbM9va+oQHbB:ZkmDNhnmPMoKmG2VY/G1WA==:9bc6db54bc6789abc2efc2b65cf4716a694d56e4029b514af24a7e5d6d61bb6c9695469bb7bf7b9a08cc2496ed971de36a82cfe55592e9c6d5f6c91432bcda7f:b75b2ef87876df7910dcfec92b6b6330a51ea83567acbf07858893e905de95c92618bdaf63ad20cf6d49ee1b840742da8016008764febd0a0a302d1ea201654d --passphrase omagawd --decrypt

Passphrase used: omagawd
Result:
surprise attack, mcdonalds, tomorrow morning
```

# License
```
This project is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, 
either version 3 of the License, or (at your option) any later version.

This project is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this code. 
If not, see <https://www.gnu.org/licenses/>. 
```