import os
import sys
import time
import hashlib
import numpy

SIZE_OF_BLOCK = 512 #bits
SIZE_OF_INTEGER = 8 #bits
SIZE_OF_BLOCK_FOR_FILE = pow(2,SIZE_OF_INTEGER)* SIZE_OF_INTEGER #bits
BLOCK_FOR_FILE_BITS = SIZE_OF_BLOCK_FOR_FILE >> 3 #bits
NUMBER_OF_BLOCKS = pow(2,SIZE_OF_INTEGER)
LENGTH_OF_BLOCK = SIZE_OF_BLOCK/4 #64 bytes, 128 characters
MODULUS = NUMBER_OF_BLOCKS

def generateBlockKey(hashedSecretKey, numberOfBlocks, *filePaths):
	filechunks = []

	for index,filePath in enumerate(filePaths):
		filechunks.append([])
		f = file(filePath,"rb")
		while len(filechunks[index]) < numberOfBlocks:
			filechunks[index].append(f.read(BLOCK_FOR_FILE_BITS).encode('hex'))
	
	secretKeyChunks = hashedSecretKey
	blockKeys = []
	currBlock = 0
	length = len(secretKeyChunks)

	index = 0
	secretKey_Which = []
	orderMapping = [None]*NUMBER_OF_BLOCKS

	while index < length:
		value = int(secretKeyChunks[index:index+2],16)
		#collision resolution
		while orderMapping[value]:
			value = (value + 1) % MODULUS
		
		orderMapping[value]=1
		secretKey_Which.append(value)
		index += 2


	while currBlock < numberOfBlocks:
		blockKey = ""
		# 8 bit integer in secret key
		index = 0
		while index < length:
			index_of_block = secretKey_Which[index>>1]
			# file chaining
			for individualFile in filechunks:
				offset = index_of_block
				index_of_block = int(individualFile[currBlock][offset:offset+2],16)
			blockKey += individualFile[currBlock][offset:offset+2]
			index += 2
		blockKeys.append(blockKey)
		currBlock+=1

	return blockKeys

def chunks(l, n):
    for i in xrange(0, len(l), n):
        yield l[i:i+n]

def protectSecretKey(secretKey, nonce1, nonce2):
	print "PreSharedKey(hex) : " + secretKey
	secretKeyInt = int(secretKey,16)

	print "Nonce1 : " + nonce1
	nonce1Int = int(nonce1,16)

	print "Nonce2 : " + nonce2 
	nonce2Int = int(nonce2,16)

	sessionSecretKey = secretKeyInt ^ nonce1Int ^ nonce2Int
	sessionSecretKey = hashlib.sha512('%x'%sessionSecretKey).hexdigest()
	print "Session Secret Key : " + sessionSecretKey

	return sessionSecretKey

def encrypt(secretKey, nonce1, nonce2, plaintextFile, *filePaths):
	print "Secret Key: %s"%secretKey
	sessionSecretKey = protectSecretKey(secretKey,nonce1,nonce2)
	print "-" * 80

	plaintext = file(plaintextFile, "rb").read()
	plaintextHex = plaintext.encode('hex')
	plaintextChunks = list(chunks(plaintextHex,LENGTH_OF_BLOCK))

	blockKeys = generateBlockKey(sessionSecretKey,len(plaintextChunks), *filePaths)

	cipherText = ""
	for index,plainChunk in enumerate(plaintextChunks):
		sessionKeyForChunk = blockKeys[index]
		paddedPlainChunk = plainChunk.ljust(LENGTH_OF_BLOCK,'0')
		cipherTextForChunk = "%x"%(int(paddedPlainChunk,16) ^ int(sessionKeyForChunk,16))
		cipherTextForChunk = cipherTextForChunk.rjust(LENGTH_OF_BLOCK,'0')
		cipherText += cipherTextForChunk

	return cipherText

def encryptCBC(secretKey, nonce1, nonce2, plaintextFile, *filePaths):
	print "Secret Key: %s"%secretKey
	sessionSecretKey = protectSecretKey(secretKey,nonce1,nonce2)
	print "-" * 80
	plaintext = file(plaintextFile, "rb").read()
	plaintextHex = plaintext.encode('hex')
	plaintextChunks = list(chunks(plaintextHex,LENGTH_OF_BLOCK))

	blockKeys = generateBlockKey(sessionSecretKey,len(plaintextChunks), *filePaths)

	cipherText = ""
	previousCipherText = 0
	for index,plainChunk in enumerate(plaintextChunks):
		sessionKeyForChunk = blockKeys[index]
		paddedPlainChunk =  plainChunk.ljust(LENGTH_OF_BLOCK,'0')
		cipherTextForChunk = "%x"%(previousCipherText ^ int(paddedPlainChunk,16) ^ int(sessionKeyForChunk,16))
		cipherTextForChunk = cipherTextForChunk.rjust(LENGTH_OF_BLOCK,'0')
		cipherText += cipherTextForChunk

	return cipherText

def decryptCBC(secretKey, nonce1, nonce2, cipherTextFile, *filePaths):
	print "Secret Key: %s"%secretKey
	sessionSecretKey = protectSecretKey(secretKey,nonce1,nonce2)
	print "-" * 80
	cipherText = file(cipherTextFile, "rb").read()
	cipherTextHex = cipherText.encode('hex')
	cipherTextChunks = list(chunks(cipherTextHex,LENGTH_OF_BLOCK))

	blockKeys = generateBlockKey(sessionSecretKey,len(cipherTextChunks), *filePaths)

	plainText = ""
	previousCipherText = 0
	for index,cipherChunk in enumerate(cipherTextChunks):
		sessionKeyForChunk = blockKeys[index]
		plainTextForChunk = "%x"% (previousCipherText^int(cipherChunk,16) ^ int(sessionKeyForChunk,16))
		plainTextForChunk = plainTextForChunk.rjust(LENGTH_OF_BLOCK,'0')
		plainText += plainTextForChunk
	return plainText

#############################################################################################

def sampleECB():
	secretKey = file("secretkey","rb").read()
	nonce1 = file("nonce1","rb").read()
	nonce2 = file("nonce2","rb").read()
	cipherText= encrypt(secretKey, nonce1, nonce2, "samplePlainText.txt", "file1.m4a","file2.avi")
	print "CipherText: %s"%cipherText.decode('hex')
	temp = file("/tmp/input","wb")
	temp.write(cipherText.decode('hex'))
	temp.close()
	print "-" * 80
	print "PlainText: %s"%encrypt(secretKey, nonce1, nonce2, "/tmp/input", "file1.m4a","file2.avi").decode('hex')	

def sampleCBC():
	secretKey = file("secretkey","rb").read()
	nonce1 = file("nonce1","rb").read()
	nonce2 = file("nonce2","rb").read()
	cipherText= encryptCBC(secretKey, nonce1, nonce2, "samplePlainText.txt", "file1.m4a","file2.avi")
	print "CipherText: %s"%cipherText.decode('hex')
	temp = file("/tmp/input","wb")
	temp.write(cipherText.decode('hex'))
	temp.close()
	print "-" * 80
	print "PlainText: %s"%decryptCBC(secretKey, nonce1, nonce2, "/tmp/input", "file1.m4a","file2.avi").decode('hex')	

def sampleBMP():
	secretKey = file("secretkey","rb").read()
	nonce1 = file("nonce1","rb").read()
	nonce2 = file("nonce2","rb").read()
	cipherText= encrypt(secretKey, nonce1, nonce2, "sample.bmp", "file1.m4a","file2.avi")
	temp = file("./encryptedSampleECB.bmp","wb")
	temp.write(cipherText.decode('hex'))
	temp.close()

def main(argv):
	sampleECB()
	sampleCBC()
	n1 = time.time()
	sampleBMP()
	n2 = time.time()
	print "time taken: %f" % (n2-n1)


if __name__ == "__main__":
	main(sys.argv)