#!/usr/bin/env python
#  =================================================================
#  	SOURCE FILE: encryption.py
#  
#
#	DATE: Dec 4th 2017
#  
#  
#  	AUTHOR: Paul Cabanez, Justin Chau
#
#	
#	DESCRIPTION: encryption and decryption functions for data
#		
#	
#
#	LAST REVISED: Nov 22th 2017
#  =================================================================

from Crypto.Cipher import AES
import base64

MASTER_KEY = "EncryptDecryptDataSentByBackdoor"
SALT = "JstinPaulCabanez"
#  =================================================================
#  name: encryption
#  @param:
#		text 			- the plaintext that will be encrypted
#
#  @return
#		encryptedText 	- the encrypted plaintext
#
#  description: encrypts data given
#  =================================================================
def encryption(text):
	secretKey = AES.new(MASTER_KEY,AES.MODE_CFB, SALT)
	padding = (AES.block_size - len(str(text)) % AES.block_size) * "\0"
	plainTextWithPadding = str(text) #+ padding
	
	cipherText = base64.b64encode(secretKey.encrypt(plainTextWithPadding))
  
	return cipherText
	
#  =================================================================
#  name: decryption
#  @param:
#		encryptedText 	- the encrypted text that will be decrypted
#
#  @return
#		plainText 		- the decrypted text
#
#  description: decrypts encrypted data given
#  ================================================================= 	
def decryption(encrypted_text):
	missing_padding = len(encrypted_text) % 4
	if missing_padding != 0:
		encrypted_text += b'='* (4 - missing_padding)
	secretKey = AES.new(MASTER_KEY,AES.MODE_CFB, SALT)
	plainTextWithPadding = secretKey.decrypt(base64.b64decode(encrypted_text))
  
	return plainTextWithPadding
