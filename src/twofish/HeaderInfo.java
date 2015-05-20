package twofish;

import java.util.List;

/**
 * Created by Grzegorz on 2015-05-04.
 */

/**
 * Represents the information contained within encrypted file's header.
 */
public class HeaderInfo {
	public String algorithm;        // encryption algorithm, e.g. Twofish or AES
	public int keysize;             // size of session key in bits
	public int subblockSize;        // only makes sense for CFB and OFB
	public CipherMode cipherMode;   // cipher mode of operation, e.g. CBC or OFB
	public byte[] iv;               // initialization vector
	public List<User> users;
}
