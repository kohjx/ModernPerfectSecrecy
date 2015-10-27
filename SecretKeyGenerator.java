import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;

public class SecretKeyGenerator {

    public static void main(String[] args) {
        try {
	    // Initialize a secure random number generator
	    SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
		
	    int length = 512;
	    StringBuilder sb = new StringBuilder(length);
	    for (int i = 0; i < length; i++) {
		sb.append(secureRandom.nextInt(2)); 
	    }
	    System.out.println(sb.toString());
	    BigInteger bigInteger = new BigInteger(sb.toString(), 2);
	    System.out.println(bigInteger.toString(16));	    

	} catch (NoSuchAlgorithmException noSuchAlgo) {
	    System.out.println("NoSuchAlgorithmException:" + noSuchAlgo);
	}
    }

}
