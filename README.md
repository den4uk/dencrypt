dencrypt
========

Encrypts and decrypts files using AES encryption

PyCrypto module is required.
Get source from https://pypi.python.org/pypi/pycrypto


# To encrypt a file:

```sh
$ python3 dencrypt.py <file> <password>
$ python3 dencrypt.py image.jpg Pa$$w0rd  # Example
```
This will encrypt the file and transform image.jpg to image.jpg.crpt


# To decrypt a file:

```sh
$ python3 dencrypt.py <crptfile>
$ python3 dencrypt.py image.jpg.crpt  # Example
```
You will be requested to enter a password. Upon correct passowrd the file will be decrypted. This will decrypt the file and transform image.jpg.crpt to image.jpg


DISCLAIMER: I HOLD NO RESPONSABILITY FOR ANY LOSS OF YOUR DATA IN THE PROCESS OF ENCRYPTION/DECRYPTION. MAKE SURE YOU ARE FAMILIAR WITH THE SCRIPT BEFORE USING IT.
