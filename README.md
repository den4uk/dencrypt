dencrypt
========

Encrypts and decrypts files using AES encryption

PyCrypto module is required.
Install by one of the following:
# pip3 install pycrypto
# easy_install pycrypto
or get source from https://pypi.python.org/pypi/pycrypto

To encrypt a file:
$ python3 dencrypt.py <file> <password>
eg: $ python3 dencrypt.py image.jpg Pa$$w0rd
This will transform image.jpg to image.jpg.crpt

To decrypt a file:
$ python3 dencrypt.py <crptfile>
eg: python3 dencrypt.py image.jpg.crpt
You will be requested to enter a password. Upon correct passowrd the file will be decrypted.
This will transform image.jpg.crpt to image.jpg

DISCLAIMER: I HOLD NO RESPONSABILITY FOR ANY LOSS OF YOUR DATA IN THE PROCESS OF ENCRYPTION/DECRYPTION. MAKE SURE YOU ARE FAMILIAR WITH THE SCRIPT BEFORE USING IT.
