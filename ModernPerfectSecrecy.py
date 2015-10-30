import sys,os

def generateSessionKey(hashedSecretKey, blockIndex, *filePaths):
	
	SIZE_OF_BLOCK = 512
	SIZE_OF_INTEGER = 8
	SIZE_OF_BLOCK_FOR_FILE = pow(2,SIZE_OF_INTEGER)* SIZE_OF_INTEGER

	filechunks = []

	for index,filePath in enumerate(filePaths):
		f = file(filePath,"rb")
		size = os.fstat(f.fileno()).st_size
		filechunks.append([])
		while size-f.tell() >= SIZE_OF_BLOCK_FOR_FILE/8:
			filechunks[index].append(list(chunks(f.read(SIZE_OF_BLOCK_FOR_FILE/8).encode('hex'),2)))

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
			index_of_block = int(individualFile[blockIndex][index_of_block],16)
		sessionKey.append(("%.2x"%index_of_block))
	sessionKey = ''.join(sessionKey)

	return sessionKey

def chunks(l, n):
    for i in xrange(0, len(l), n):
        yield l[i:i+n]

def main(argv):
	hashedKey = "A"*128
	print "Secret Key: %s"%hashedKey
	print "Session Key: %s"%generateSessionKey(hashedKey, 0, "file1.txt","file2.txt")

if __name__ == "__main__":
	main(sys.argv)