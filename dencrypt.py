#!/usr/bin/env python3

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# Python 3.x required module: PyCrypto
# DenCrypt - Encrypts and decrypts small files using AES encryption
# Version 0.1
# Copyright (C) 2014  Denis Sazonov  den@saz.lt
#
# This program is free software: you can redistribute it and/or modify 
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or 
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but 
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU 
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 

import sys, os.path, gzip, re
from hashlib import pbkdf2_hmac, md5
from getpass import getpass
from binascii import hexlify
try:
	from Crypto.Cipher import AES
except:
	sys.exit('**Install PyCrypto Module**\nhttps://pypi.python.org/pypi/pycrypto')
try:
	from Crypto import Random
except:
	from os import urandom

# Custom Configurations
# Where 'min' is mentioned - minimum recommended for secure ecryption
ext = '.crpt'		# Extention file for encrypted files
pad = b'{'			# Padding for encryption blocks
gzh = b'\x1f\x8b\x08\x00'	# Gzip header (do not change)
algo = 'sha256'		# Hashing algorithm (md5, sha1, sha256, etc.)
ite = 100000		# Iteration of the password (min: 1000)
IV_block_size = 16	# Initialisation Vector blocksize (do not change)
EnRemove = True		# Delete the file that is being encrypted (True/False)
DeRemove = True		# Delete the file that is being decrypted (True/False)
# Change the salt value if needed. Only change once.
salt = b'I|h\xee`~\xabc{\x04_D\x0f\xf0\x9d:'	# (min: 16 bytes)
key_size = AES.key_size[2]			# Encryption strength (16, 24, 32)


def DoKey(key):
	return pbkdf2_hmac(algo, key.encode(), salt, ite, key_size)


def Encrypt(key, data):
	key = DoKey(key)
	try:
		IV = Random.new().read(IV_block_size)
	except:
		IV = urandom(IV_block_size)
	obj_en = AES.new(key, AES.MODE_CBC, IV)
	zdata = gzip.compress(data)
	if len(zdata) % AES.block_size != 0:
		zdata = zdata + pad*(AES.block_size - (len(zdata) % AES.block_size))
	EnData = obj_en.encrypt(zdata) + IV
	#print('+'*50)
	#print('+ MD5SUM:\t{}'.format(md5(data).hexdigest()))
	#print('+ PBKDF2:\t{}/{}'.format(algo, ite))
	#print('+   Salt:\t{}'.format(hexlify(salt).decode()))
	#print('+     IV:\t{}'.format(hexlify(IV).decode()))
	#print('+'*50)
	return EnData


def Decrypt(key, edata, IV):
	key = DoKey(key)
	obj_de = AES.new(key, AES.MODE_CBC, IV)
	zdata = obj_de.decrypt(edata[:-IV_block_size])
	data = gzip.decompress(zdata.rstrip(pad))
	#print('+'*50)
	#print('+ MD5SUM:\t{}'.format(md5(data).hexdigest()))
	#print('+'*50)
	return data


def TestPass(key, Block_One, IV):
	key = DoKey(key)
	obj_det = AES.new(key, AES.MODE_CBC, IV)
	EnData = obj_det.decrypt(Block_One)
	if re.match(gzh, EnData):
		return True


def Main():
	# TO ENCRYPT
	if len(sys.argv) == 3:
		if os.path.isfile(sys.argv[1]):
			if os.path.basename(sys.argv[0]) == os.path.basename(sys.argv[1]): sys.exit('>> Do not encrypt yourself!')
			in_file = open(sys.argv[1], 'rb').read()
			with open(sys.argv[1]+ext, 'wb') as out_file:
				out_file.write(Encrypt(sys.argv[2], in_file))
				if EnRemove: os.remove(sys.argv[1])
		else:
			sys.exit('>> File not found!')
	# TO DECRYPT
	elif len(sys.argv) == 2:
		if os.path.isfile(sys.argv[1]):
			if os.path.splitext(sys.argv[1])[1] == ext:
				in_file = open(sys.argv[1], 'rb')
				Block_One = in_file.read(AES.block_size)
				in_file.seek(-IV_block_size, 2)
				get_iv = in_file.read()
				de_key = getpass()
				if de_key != '':
					if TestPass(de_key, Block_One, get_iv):
						in_file = open(sys.argv[1], 'rb').read()
						with open(os.path.splitext(sys.argv[1])[0], 'wb') as out_file:
							out_file.write(Decrypt(de_key, in_file, get_iv))
							if DeRemove: os.remove(sys.argv[1])
					else:
						sys.exit('>> Wrong password!')
				else:
					sys.exit('>> No password specified!')
			else:
				sys.exit('>> Specify encryption password after the filename...')
		else:
			sys.exit('>> File not found!')
	else:
		sys.exit('>> Usage:\nTo Encrypt: ${0} <file> <password>\nTo Decrypt: ${0} <crypted_file>'.format(sys.argv[0]))


if __name__ == '__main__':
	Main()
