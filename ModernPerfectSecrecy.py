import os
import sys
import hashlib

SIZE_OF_BLOCK = 512
SIZE_OF_INTEGER = 8
SIZE_OF_BLOCK_FOR_FILE = pow(2,SIZE_OF_INTEGER)* SIZE_OF_INTEGER

def generateSessionKey(hashedSecretKey, blockIndex, *filePaths):
	filechunks = []

	for index,filePath in enumerate(filePaths):
		f = file(filePath,"rb")
		f.seek(blockIndex*SIZE_OF_BLOCK_FOR_FILE/8)
		filechunks.append(list(chunks(f.read(SIZE_OF_BLOCK_FOR_FILE/8).encode('hex'),2)))

	secretKeyChunks = chunks(hashedSecretKey,2)
	orderMapping = [None]*(pow(2,SIZE_OF_INTEGER))
	MODULUS = pow(2,SIZE_OF_INTEGER)

	sessionKey = []
	# 8 bit integer in secret key
	for index in secretKeyChunks:
		value = int(index,16)
		# collision resolution
		while orderMapping[value] == 1:
			value = (value + 1) % MODULUS
		orderMapping[value]=1

		index_of_block = value
		# file chaining
		for individualFile in filechunks:
			index_of_block = int(individualFile[index_of_block],16)
		sessionKey.append(("%.2x"%index_of_block))
	sessionKey = ''.join(sessionKey)

	return sessionKey

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
	plaintextChunks = chunks(plaintextHex,SIZE_OF_BLOCK/8*2)

	cipherText = ""
	for index,plainChunk in enumerate(plaintextChunks):
		sessionKeyForChunk = generateSessionKey(sessionSecretKey, index, *filePaths)
		paddedPlainChunk =  plainChunk.ljust(SIZE_OF_BLOCK/8*2,'0')
		cipherTextForChunk = "%.128x"% (int(paddedPlainChunk,16) ^ int(sessionKeyForChunk,16))
		cipherText += cipherTextForChunk
	return cipherText

def encryptCBC(secretKey, nonce1, nonce2, plaintextFile, *filePaths):
	print "Secret Key: %s"%secretKey
	sessionSecretKey = protectSecretKey(secretKey,nonce1,nonce2)
	print "-" * 80
	plaintext = file(plaintextFile, "rb").read()
	plaintextHex = plaintext.encode('hex')
	plaintextChunks = chunks(plaintextHex,SIZE_OF_BLOCK/8*2)

	cipherText = ""
	previousCipherText = 0
	for index,plainChunk in enumerate(plaintextChunks):
		sessionKeyForChunk = generateSessionKey(sessionSecretKey, index, *filePaths)
		paddedPlainChunk =  plainChunk.ljust(SIZE_OF_BLOCK/8*2,'0')
		cipherTextForChunk = "%.128x"% (previousCipherText^int(paddedPlainChunk,16) ^ int(sessionKeyForChunk,16))
		previousCipherText = int(cipherTextForChunk,16)
		cipherText += cipherTextForChunk
	return cipherText

def decryptCBC(secretKey, nonce1, nonce2, cipherTextFile, *filePaths):
	print "Secret Key: %s"%secretKey
	sessionSecretKey = protectSecretKey(secretKey,nonce1,nonce2)
	print "-" * 80
	cipherText = file(cipherTextFile, "rb").read()
	cipherTextHex = cipherText.encode('hex')
	cipherTextChunks = chunks(cipherTextHex,SIZE_OF_BLOCK/8*2)

	plainText = ""
	previousCipherText = 0
	for index,cipherChunk in enumerate(cipherTextChunks):
		sessionKeyForChunk = generateSessionKey(sessionSecretKey, index, *filePaths)
		plainTextForChunk = "%.128x"% (previousCipherText^int(cipherChunk,16) ^ int(sessionKeyForChunk,16))
		previousCipherText = int(cipherChunk,16)
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

	cipherText= encryptCBC(secretKey, nonce1, nonce2, "sample.bmp", "file1.m4a","file2.avi")
	temp = file("./encryptedSampleCBC.bmp","wb")
	temp.write(cipherText.decode('hex'))
	temp.close()


def main(argv):
	sampleECB()
	sampleBMP()

if __name__ == "__main__":
	main(sys.argv)