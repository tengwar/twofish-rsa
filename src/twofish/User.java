package twofish;

import java.security.interfaces.RSAPublicKey;

/**
 * Created by Grzegorz on 2015-04-22.
 */

/**
 * Represents user (recipient) - both in file header and on recipients list in UI.
 */
public class User {
	String name;            // user's name; can also be email or whatever
	byte[] encryptedKey;    // session key encrypted with public RSA key
	RSAPublicKey pubkey;    // public RSA key

	public User(String name) {
		this.name = name;
	}

	public String toString() {
		return name;
	}
}
