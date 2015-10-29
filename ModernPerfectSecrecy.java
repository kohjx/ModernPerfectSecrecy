import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;


/**
 * Achieving perfect secrecy in the modern days with the Internet
 * The user is able to generate nonce value to send to receiving party.
 * The user is able to perform encryption/decryption by providing the following:
 *     - Pre-shared Secret key
 *     - Nonce1
 *     - Nonce2
 *     - 2 video files data
 *     - Message 
 */
public class ModernPerfectSecrecy {

	private static final int DIVISOR = 32;
	private static final int NUM_OF_FILES = 2;
	private static final int NUM_OF_ROUNDS_FUNCTION_F = 16;
	
	//Change according to the key length
	private static final int MAX_LENGTH_BIT = 512;
	private static final int MAX_LENGTH_HEX = 128;
	private static final int NUM_OF_BLOCKS_ORDER = 32;
	private static final int NUM_OF_BLOCKS_WHICH = 32;
	private static final int NUM_OF_BITS_PER_BLOCK_HASHEDKEY = 32;
	private static final int NUM_OF_BITS_PER_BLOCK_FILE = 32;
	private static final int NUM_OF_BITS_PER_BLOCK_ORDERWHICH = 8;

	private static Scanner sc;
	
	public ModernPerfectSecrecy() {
		 sc = new Scanner(System.in);
	}
	
	/*
	 *  Generate a nonce value
	 */
	public void generateNonce() {
		System.out.println();
        try {
        	long unixTime = System.currentTimeMillis() / 1000L;
        	String unixTimeHex = Long.toHexString(unixTime);
        	
            // Initialize a secure random number generator
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            int randomBitLength = MAX_LENGTH_BIT - 32;
            StringBuilder sb = new StringBuilder(randomBitLength);
            for (int i = 0; i < randomBitLength; i++) {
                sb.append(secureRandom.nextInt(2));
            }
            
            BigInteger bigInteger = new BigInteger(sb.toString(), 2);
            String hex = bigInteger.toString(16);
            System.out.println("Nonce(binary): " + sb.toString() + Long.toBinaryString(unixTime));
            System.out.println("Nonce(hex)   : " + hex + unixTimeHex);

        } catch (NoSuchAlgorithmException noSuchAlgo) {
            System.out.println("NoSuchAlgorithmException:" + noSuchAlgo);
        }
        System.out.println();
	}
	
	/*
	 * Encrypt the plaintext and print out the ciphertext in hex
	 */
	public void doEncryption() {
		System.out.println();
		int[] plainText = getUserInput("Enter your message(hex): ", "Message binary array with paddings: ");
		int[] finalKey = generateFinalKey();
		int[] cipherTextArray = xorArray(plainText, finalKey);
		String cipherText = convertBinaryArrayToString(cipherTextArray);
        BigInteger bigInteger = new BigInteger(cipherText, 2);
        System.out.println("CipherText(hex)   : " + bigInteger.toString(16));
        
		System.out.println();
	}
	
	/*
	 * Decrypt the ciphertext and print out the plaintext in hex.
	 */
	public void doDecryption() {
		System.out.println();
		int[] cipherText = getUserInput("Enter your cipherText(hex): ", "cipherText binary array with paddings: ");
		int[] finalKey = generateFinalKey();
		int[] plainTextArray = xorArray(cipherText, finalKey);
		String plainText = convertBinaryArrayToString(plainTextArray);
        BigInteger bigInteger = new BigInteger(plainText, 2);
        System.out.println("PlainText(hex)   : " + bigInteger.toString(16));
		System.out.println();
	}
	
	/*
	 * Get the relevant information required from the user to compute the final key
	 */
	private int[] generateFinalKey() {
		int[] preSharedKey = getUserInput("Enter your Pre-Shared Secret Key(hex): ", "Pre-shared key binary array with paddings: ");
		int[] nonce1 = getUserInput("Enter your nonce1(hex): ", "Nonce1 binary array with paddings: ");
		int[] nonce2 = getUserInput("Enter your nonce2(hex): ", "Nonce2 binary array with paddings: ");
		int[] file1 = getUserInput("Enter your file1 data(hex): ", "File1 binary array with paddings: ");
		int[] file2 = getUserInput("Enter your file2 data(hex): ", "File2 binary array with paddings: ");
		int[] file = concatTwoFilesArray(file1, file2);
		
		int[] nonce1Key = xorArray(preSharedKey, nonce1);
		int[] orderwhichKey = xorArray(nonce1Key, nonce2);
		int[] orderKey = convert8bitsToIntegerArray(orderwhichKey, 0);
		int[] whichKey = convert8bitsToIntegerArray(orderwhichKey, (MAX_LENGTH_BIT / 2));
		int[] hashedKey = getSHA512Hash(orderwhichKey);
		int[] finalKey = doFunctionF(hashedKey, orderKey, whichKey, file);
		
		return finalKey;
	}
	
	/*
	 *  Function F
	 */
	private int[] doFunctionF(int[] hashedKey, int[] orderKey, int[] whichKey, int[] file) {
		int startIndexH, currentStartIndexF, blockIndexF, startIndexF, subBlockIndex;
		int temp;
		int[] finalKey = new int[MAX_LENGTH_BIT];
		int[] tempArray = new int[MAX_LENGTH_BIT / 2];
		for (int x = 0; x < NUM_OF_ROUNDS_FUNCTION_F; x++) {
			startIndexH = x * NUM_OF_BITS_PER_BLOCK_HASHEDKEY;
			for (int i = 0; i < NUM_OF_BLOCKS_ORDER; i++) {
				currentStartIndexF = i * NUM_OF_BITS_PER_BLOCK_FILE;
				blockIndexF = orderKey[i] % DIVISOR;
				startIndexF = blockIndexF * NUM_OF_BITS_PER_BLOCK_FILE;
				for (int j = 0; j < NUM_OF_BITS_PER_BLOCK_FILE; j++) {
					temp = file[currentStartIndexF];
					file[currentStartIndexF] = file[startIndexF + j];
					file[startIndexF + j] = temp;
				}
			}
			
			for (int i = 0; i < NUM_OF_BLOCKS_WHICH; i++) {
				currentStartIndexF = i * NUM_OF_BITS_PER_BLOCK_FILE;
				subBlockIndex = whichKey[i] % DIVISOR;
				finalKey[startIndexH + i] = hashedKey[startIndexH + i] ^ file[currentStartIndexF + subBlockIndex];
			}
			tempArray = whichKey;
			orderKey = whichKey;
			whichKey = tempArray;
		}
		return finalKey;
	}
	
	/*
	 * Every element of array a XOR with the corresponding index of array b
	 */
	private int[] xorArray(int[] a, int[] b) {
		int[] c = new int[MAX_LENGTH_BIT];
		for (int i = 0; i < MAX_LENGTH_BIT; i++) {
			c[i] = a[i] ^ b[i];
		}
		return c;
	}
	
	/*
	 * Do a SHA-512 hashing on the binaryArray
	 */
	private int[] getSHA512Hash(int[] binaryArray) {
        try {
        	String binary = convertBinaryArrayToString(binaryArray);
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
            messageDigest.update(binary.getBytes());
            StringBuffer sb = new StringBuffer();
            for (byte b : messageDigest.digest()) {
            	sb.append(Integer.toHexString(0xff & b));
            }
            return convertHexToBinaryArray(sb.toString());
        } catch (NoSuchAlgorithmException noSuchAlgo) {
        	System.out.println("NoSuchAlgorithmException:" + noSuchAlgo);
        }
        return null;
	}
	
	/*
	 * Get the user hex input string and convert them into binaryArray.
	 */
	private int[] getUserInput(String inputMessage, String outputMessage) {
		System.out.print("\n" + inputMessage);
		String input = sc.next();
		System.out.println();
		
		int[] binaryArray = convertHexToBinaryArray(input);
		System.out.println(outputMessage);
		System.out.println(Arrays.toString(binaryArray));
		
		return binaryArray;
	}

	/*
	 * Convert a hex string into a binaryArray
	 */
	private int[] convertHexToBinaryArray(String hex) {
		if (hex.length() > MAX_LENGTH_HEX) {
			return null;
		}
		int[] binaryArray = new int[MAX_LENGTH_BIT];
		
		BigInteger bigInteger = new BigInteger(hex, 16);
		String binary = bigInteger.toString(2);
		System.out.println("Hex to Binary: ");
		System.out.println(binary);

		int bitsToPad = MAX_LENGTH_BIT - binary.length();
		for (int i = 0; i < bitsToPad; i++) {
            binaryArray[i] = 0;
        }
		
		for (int i = bitsToPad; i < MAX_LENGTH_BIT; i++) {
            binaryArray[i] = Integer.parseInt(binary.charAt(i - bitsToPad) + "");
        }
		
		return binaryArray;
	}
	
	/*
	 * Convert the binaryArray into a string
	 */
	private String convertBinaryArrayToString(int[] binaryArray) {
		StringBuilder sb = new StringBuilder(MAX_LENGTH_BIT);
        for (int i = 0; i < MAX_LENGTH_BIT; i++) {
            sb.append(binaryArray[i]);
        }
        
		return sb.toString();
	}
	
	/*
	 * Convert every 8 elements(8 bits) of the binaryArray into an integer.  
	 */
	private int[] convert8bitsToIntegerArray(int[] binaryArray, int startIndex) {
		int numOfBlocks = ( (MAX_LENGTH_BIT / 2) / NUM_OF_BITS_PER_BLOCK_ORDERWHICH);
		int[] integerArray = new int[numOfBlocks];
        for (int i = 0; i < numOfBlocks; i++) {
        	StringBuilder sb = new StringBuilder(NUM_OF_BITS_PER_BLOCK_ORDERWHICH);
        	for (int j = 0; j < NUM_OF_BITS_PER_BLOCK_ORDERWHICH; j++) {
        		sb.append(binaryArray[startIndex + j]);
        	}
        	integerArray[i] = Integer.parseInt(sb.toString(), 2);
        	startIndex += NUM_OF_BITS_PER_BLOCK_ORDERWHICH;
        }
		return integerArray;
	}
	
	/*
	 * Merge two files array into one array
	 */
	public int[] concatTwoFilesArray(int[] file1, int[] file2) {
		int[] newFileArray = new int[MAX_LENGTH_BIT * NUM_OF_FILES];
		System.arraycopy(file1, 0, newFileArray, 0, file1.length);
		System.arraycopy(file2, 0, newFileArray, file1.length, file2.length);
		return newFileArray;
	}
	
	/*
	 *  Print menu
	 */
	public void printMenu() {
		System.out.println("1. Generate a Nonce value");
		System.out.println("2. Encryption");
		System.out.println("3. Decryption");
		System.out.println("0. Exit ");
		System.out.print("Choice: ");
	}
	
	public static void main(String[] args) {
		ModernPerfectSecrecy mps = new ModernPerfectSecrecy();
		String input = "";
		do {
			mps.printMenu();
			input = sc.next();
			switch(input) {
				case "1":
					mps.generateNonce();
					break;
				case "2":
					mps.doEncryption();
					break;
				case "3":
					mps.doDecryption();
					break;
				default:
					break;
			}		
		} while(!input.equalsIgnoreCase("0"));
	}
}
