package twofish;

import java.util.List;

/**
 * Created by Grzegorz on 2015-05-04.
 */
public class HeaderInfo {
	public String algorithm;
	public int keysize;
	public CipherMode cipherMode;
	public byte[] iv;
	public List<User> users;
}
