#include <stdio.h>
#include <stdarg.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

#define _FILE_OFFSET_BITS 64

int SIZE_OF_BLOCK; //bits
int SIZE_OF_INTEGER; //bits
int SIZE_OF_BLOCK_FOR_FILE; //bits
int BLOCK_FOR_FILE_BITS; //should be bytes not bits
int NUMBER_OF_BLOCKS;
int LENGTH_OF_BLOCK; //64 bytes, 128 characters
int LENGTH_OF_BLOCK_IN_BYTES; // 64
int MODULUS;

struct node {
  char data[65];
  struct node *next;
};

unsigned char** generateBlockKey(char* sessionKey,int numberOfChunks,int numOfFile, char** listOfFiles) {

	//We only require numberOfChunks from each file
	char*** filechunks = malloc(sizeof(char**) * numOfFile);
	int i;
	for (i = 0; i<numOfFile;++i) {
		if ( (filechunks[i] = malloc(sizeof(char*)*numberOfChunks)) == NULL) {

		}
		int x;
		for (x=0;x<numberOfChunks;++x) {
			if ( (filechunks[i][x] = malloc(sizeof(char)*(NUMBER_OF_BLOCKS+1))) == NULL) {

			}
		}
	}

	for (i = 0;i < numOfFile; ++i) {
		char* filePath = listOfFiles[i];
		char* mode = "rb";
		FILE* inputFile = fopen(filePath, mode);

		if (inputFile == NULL) {
			fprintf(stderr, "Can't open input file provided!\n");
  			exit(1);
		}
		int num = 0;
		while (!feof(inputFile) && num < numberOfChunks) {
			fread(filechunks[i][num], 1, NUMBER_OF_BLOCKS, inputFile);
			num++;
		}
		fclose(inputFile);
	}

	int lengthOfKey = LENGTH_OF_BLOCK;
	int lengthOfBlockKey = LENGTH_OF_BLOCK_IN_BYTES;
	int secretKey_Which[lengthOfBlockKey]; // 2 char per integer, so half of length , 64 bytes
	int mapping[NUMBER_OF_BLOCKS];
	memset(mapping,0,sizeof(mapping));
	for (i = 0; i < LENGTH_OF_BLOCK_IN_BYTES; ++i) {
		unsigned char value = sessionKey[i];

		while(mapping[value]==1) {
			value = (value+1) % MODULUS;
		}
		mapping[value]=1;
		secretKey_Which[i]=value;
	}

	unsigned char ** blockKeys = malloc( sizeof(char*) * (numberOfChunks));
	for (i=0; i< numberOfChunks;++i) {
		if ( (blockKeys[i] = malloc(lengthOfBlockKey+1)) == NULL) {

		}
	}
	for (i=0; i<numberOfChunks; ++i) {
		unsigned char blockKey[lengthOfBlockKey];
		memset(blockKey,0,sizeof(blockKey));
		int index;
		for (index=0;index<lengthOfBlockKey;++index) {
		 	int indexOfBlock = secretKey_Which[index];
			// file chainings
			int fileIndex;
			for (fileIndex = 0; fileIndex < numOfFile;++fileIndex) {
				unsigned char next_index = filechunks[fileIndex][i][indexOfBlock];
				indexOfBlock = next_index;
			}
			blockKeys[i][index] = indexOfBlock;
		}
	}

	return blockKeys;
}

char* generateSessionSecretKey(char* secretKey,char* nonce1,char* nonce2) {
	long long secretKey_int = (int) strtoll(secretKey,NULL,16);
	long long nonce1_int = (int)strtoll(nonce1,NULL,16);
	long long nonce2_int = (int)strtoll(nonce2,NULL,16);

	secretKey_int = secretKey_int ^ nonce1_int ^ nonce2_int;
	char* sessionKey = malloc(LENGTH_OF_BLOCK_IN_BYTES+1);
	snprintf(sessionKey, LENGTH_OF_BLOCK_IN_BYTES+1,"%64llX", secretKey_int);

	SHA512(sessionKey, sizeof(sessionKey)-1, sessionKey); 

	return sessionKey;
}

unsigned char* encrypt(char* secretKey, char* nonce1, char* nonce2, char* plaintextFile, int numOfFile, char** listOfFiles) {
	char* sessionKey = generateSessionSecretKey(secretKey, nonce1, nonce2);

	char* mode = "rb";
	FILE* inputFile = fopen(plaintextFile, mode);

	if (inputFile == NULL) {
		fprintf(stderr, "Can't open plaintext file provided! %s\n",plaintextFile);
		exit(1);
	}

	struct node *root;
	root = (struct node *) malloc( sizeof(struct node));

	struct node *cur;
	cur = root;
	fseek(inputFile, 0, SEEK_END);
    long f_size = ftell(inputFile);
    fseek(inputFile, 0, SEEK_SET);

	int numberOfChunks = ceil((double)f_size/LENGTH_OF_BLOCK_IN_BYTES);
	int i = 0;
	while (!feof(inputFile) && i < numberOfChunks) {
		i++;
		fread(cur->data, 1, LENGTH_OF_BLOCK_IN_BYTES, inputFile);
		struct node *next = (struct node *) malloc( sizeof(struct node));
		cur->next=next;
		cur=next;
	}
	fclose(inputFile);

	unsigned char**  blockKeys = generateBlockKey(sessionKey,numberOfChunks,numOfFile, listOfFiles);

	unsigned char* cipherText= malloc(numberOfChunks*LENGTH_OF_BLOCK_IN_BYTES+1);
	cur = root;

	i = 0;
	int x= 0;
	while(cur->next != NULL) {
		unsigned char* blockKey = blockKeys[i];
		unsigned char* data = (unsigned char*)cur->data;

		unsigned char result[LENGTH_OF_BLOCK_IN_BYTES];

		int index;
		for (index = 0;index < LENGTH_OF_BLOCK_IN_BYTES; ++index) {
			x++;
			int offset = i * LENGTH_OF_BLOCK_IN_BYTES;
			cipherText[offset+index] = blockKey[index] ^ data[index];
		}
		cur = cur->next;
		i++;
	}

	fwrite(cipherText, 1, f_size, stdout);

	return cipherText;
}

char* readFile(char* filePath) {
	FILE *f = fopen(filePath, "rb");
	if (f == NULL) {
		fprintf(stderr, "Can't open file provided! %s\n",filePath);
		exit(1);
	}

	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	char *string = malloc(fsize + 1);
	fread(string, fsize, 1, f);
	fclose(f);

	string[fsize] = 0;

	return string;
}

int main(int argc, char* argv[]) {
	SIZE_OF_BLOCK = 512; //bits
	SIZE_OF_INTEGER = 8; //bits
	NUMBER_OF_BLOCKS = pow(2,SIZE_OF_INTEGER);
	MODULUS = NUMBER_OF_BLOCKS;
	SIZE_OF_BLOCK_FOR_FILE = NUMBER_OF_BLOCKS << 3; // number of bits
	LENGTH_OF_BLOCK = SIZE_OF_BLOCK >> 2; //64 bytes, 128 characters
	LENGTH_OF_BLOCK_IN_BYTES = LENGTH_OF_BLOCK>>1;

	if (argc<5) {
		printf("Usage: %s secretKeyPath nonce1Path nonce2Path plaintextfilepath file1 file2 ...", argv[0]);
	}

	char* secretKeyPath = argv[1];
	char* nonce1Path = argv[2];
	char* nonce2Path = argv[3];
	char* plaintextPath = argv[4];

	char* secretKey = readFile(secretKeyPath);
	char* nonce1 = readFile(nonce1Path);
	char* nonce2 = readFile(nonce2Path);

	char** listOfFiles = malloc(sizeof(char*) * (argc-5));
	int i;
	for (i=0;i<argc-5;++i) {
		listOfFiles[i] = argv[i+5];
	}

	encrypt(secretKey,nonce1,nonce2,plaintextPath,(argc-5),listOfFiles);
	return 0;
}

