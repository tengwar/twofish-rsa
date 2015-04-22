package twofish;

import java.security.interfaces.RSAPublicKey;

/**
 * Created by Grzegorz on 2015-04-22.
 */
public class User {
	String name;
	byte[] encryptedKey;
	RSAPublicKey pubkey;

	public User(String name) {
		this.name = name;
	}

	public String toString() {
		return name;
	}
}
