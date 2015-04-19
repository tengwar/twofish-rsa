package twofish;

/**
 * Created by Grzegorz on 2015-04-19.
 */

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Utils {
	public static byte[] twofishEncrypt(byte[] data, SecretKey key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
		Cipher cipher = null;
		byte[] encrypted = null;
		// preparation
		cipher = Cipher.getInstance("Twofish/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key);

		// really encrypt stuff
		encrypted = cipher.doFinal(data);

		return encrypted;
	}

	// TODO throws Exception?
	public static byte[] twofishDecrypt(byte[] data, SecretKey key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
		Cipher cipher = null;
		byte[] decrypted = null;
		// preparation
		cipher = Cipher.getInstance("Twofish/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, key);

		// really encrypt stuff
		decrypted = cipher.doFinal(data);

		return decrypted;
	}

	public static SecretKey generateKey() throws NoSuchAlgorithmException {
		SecureRandom rand = new SecureRandom("lel".getBytes()); // TODO use real data for init

		KeyGenerator generator = KeyGenerator.getInstance("Twofish");
		generator.init(rand);
		SecretKey secretKey = generator.generateKey();

		return secretKey;
	}

	public static int checkMaxKeyLength(String cipher) {
		int allowedKeyLength = 0;

		try {
			allowedKeyLength = Cipher.getMaxAllowedKeyLength(cipher);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		System.out.println("The allowed key length for " + cipher + " is: " + allowedKeyLength);

		return allowedKeyLength;
	}
}
