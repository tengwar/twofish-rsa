package twofish;

/**
 * Created by Grzegorz on 2015-04-19.
 */

import javafx.concurrent.Task;
import javafx.scene.control.Alert;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class Utils {
	public static byte[] encrypt(byte[] data, HeaderInfo info) {
		byte[] file = null;

		try {
			// generate key
			SecretKey sessionKey = generateKey(info.keysize);

			// prepare cipher
			Cipher cipher;
			if (info.cipherMode == CipherMode.CFB || info.cipherMode == CipherMode.OFB) {
				cipher = Cipher.getInstance("Twofish/" + info.cipherMode.toString() +
						String.valueOf(info.subblockSize) + "/PKCS7Padding");
			} else {
				cipher = Cipher.getInstance("Twofish/" + info.cipherMode.toString() + "/PKCS7Padding");
			}
			cipher.init(Cipher.ENCRYPT_MODE, sessionKey);

			// encrypt
			byte[] encrypted = cipher.doFinal(data);

			// create XML document
			DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
			Document doc = db.newDocument();

			// root node
			Element root = doc.createElement("EncryptedFileHeader");
			doc.appendChild(root);

			// algorithm node
			Element algorithm = doc.createElement("Algorithm");
			algorithm.appendChild(doc.createTextNode(info.algorithm));
			root.appendChild(algorithm);

			// key size node
			Element keysize = doc.createElement("KeySize");
			// We could get size from HeaderInfo, but to always get the real value even if code changes we do this:
			keysize.appendChild(doc.createTextNode(String.valueOf(sessionKey.getEncoded().length * 8)));
			root.appendChild(keysize);

			// subblock size
			if (info.cipherMode == CipherMode.CFB || info.cipherMode == CipherMode.OFB) {
				assert info.subblockSize != 0;
				Element subblockSizeNode = doc.createElement("SegmentSize");
				subblockSizeNode.appendChild(doc.createTextNode(String.valueOf(info.subblockSize)));
				root.appendChild(subblockSizeNode);
			}

			// cipher mode node
			Element modeNode = doc.createElement("CipherMode");
			modeNode.appendChild(doc.createTextNode(info.cipherMode.toString()));
			root.appendChild(modeNode);

			// IV node
			if (cipher.getIV() != null) {
				Element iv = doc.createElement("IV");
				iv.appendChild(doc.createTextNode(Base64.getEncoder().encodeToString(cipher.getIV())));
				root.appendChild(iv);
			}

			// users node
			Element usersNode = doc.createElement("ApprovedUsers");
			root.appendChild(usersNode);

			// add users
			for (User user : info.users) {
				Element userNode = doc.createElement("User");
				usersNode.appendChild(userNode);
				Element nameNode = doc.createElement("Name");
				nameNode.appendChild(doc.createTextNode(user.name));
				userNode.appendChild(nameNode);
					// encrypt session key
					Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
					rsa.init(Cipher.ENCRYPT_MODE, user.pubkey);
					byte[] key = rsa.doFinal(sessionKey.getEncoded());
				Element encryptedKey = doc.createElement("SessionKey");
				encryptedKey.appendChild(doc.createTextNode( Base64.getEncoder().encodeToString(key) ));
				userNode.appendChild(encryptedKey);
			}

			// write the XML
			Transformer transformer = TransformerFactory.newInstance().newTransformer();
			transformer.setOutputProperty(OutputKeys.INDENT, "yes");                            // use indentation
			transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");    // indent with 4 spaces
			DOMSource source = new DOMSource(doc);
			ByteArrayOutputStream xmlBaos = new ByteArrayOutputStream();
			StreamResult result = new StreamResult(xmlBaos);
			// Output to console for testing
			//StreamResult result = new StreamResult(System.out);
			// Output to file
			//StreamResult result = new StreamResult(new File(filePath));
			transformer.transform(source, result);

			byte[] xmlBytes = xmlBaos.toByteArray();

			ByteArrayOutputStream fileBaos = new ByteArrayOutputStream();

			fileBaos.write(intToByteArray(xmlBytes.length));    // write the XML size (int is 4 bytes in Java)
			fileBaos.write(xmlBytes);                           // write the XML itself
			fileBaos.write(encrypted);                          // write the encrypted data
			file = fileBaos.toByteArray();

		} catch (ParserConfigurationException e) {
			(new Alert(Alert.AlertType.WARNING, "XML parser configuration exception.")).show();
		} catch (TransformerConfigurationException e) {
			(new Alert(Alert.AlertType.WARNING, "XML transformer configuration exception.")).show();
		} catch (TransformerException e) {
			(new Alert(Alert.AlertType.WARNING, "XML transformer exception.")).show();
		} catch (InvalidKeyException e) {
			(new Alert(Alert.AlertType.WARNING, "Twofish encryption key is invalid.")).show();
		} catch (NoSuchAlgorithmException e) {
			(new Alert(Alert.AlertType.WARNING, "Twofish algorithm is not supported, install BouncyCastle.")).show();
		} catch (NoSuchPaddingException e) {
			(new Alert(Alert.AlertType.WARNING, "Selected padding is not supported.")).show();
		} catch (BadPaddingException e) {
			(new Alert(Alert.AlertType.WARNING, "Padding is wrong.")).show();
		} catch (IllegalBlockSizeException e) {
			(new Alert(Alert.AlertType.WARNING, "That block size is not supported.")).show();
		} catch (IOException e) {
			(new Alert(Alert.AlertType.WARNING, "ByteArrayOutputStream IO exception. Shouldn't happen.")).show();
		}

		return file;
	}

	/**
	 * Creates a task that decrypts the given file using given parameters. The task updates its progress.
	 * @param user User containing a name and encrypted session key - the recipient.
	 * @param info HeaderInfo with cipher mode of operation, and maybe an IV or subblock size.
	 * @param privKeyPassword Password used for private key encryption.
	 * @param inputFilepath Path of file to be decrypted.
	 * @param outputFilepath Path where the newly decrypted file will be saved.
	 * @return A task that will decrypt the given file using given parameters.
	 */
	public static Task createDecryptTask(final String username, final String privKeyPassword, final String inputFilepath,
	                                     final String outputFilepath) {
		return new Task() {
			@Override
			protected Object call() throws Exception {
				// get file length in bytes
				File inputFile = new File(inputFilepath);
				long filesize = inputFile.length();

				try (InputStream inputStream = Files.newInputStream(Paths.get(inputFilepath));
				     OutputStream outputStream = Files.newOutputStream(Paths.get(outputFilepath))) {
					// read header size
					byte[] headerSizeBytes = new byte[4];
					if (inputStream.read(headerSizeBytes) != 4) // we can't even read the size, quit
						throw new IOException("Couldn't read header size from file.");
					int headerSize = Utils.byteArrayToInt(headerSizeBytes);

					// read header bytes
					byte[] headerBytes = new byte[headerSize];
					if (inputStream.read(headerBytes) != headerSize) // we can't read the header, quit
						throw new IOException("Couldn't read header from file.");

					// parse header
					HeaderInfo info = parseHeader(headerBytes);
					CipherMode mode = info.cipherMode; // little helper for shorter code

					// find user on the list
					User user = null;
					for (User u : info.users) {
						if (u.name.equals(username))
							user = u;
					}
					if (user == null) {// user not found on the list, abort
						throw new IllegalArgumentException("Selected user not found in file.");
					}

					// read private key
					RSAPrivateKey privkey = Utils.loadPrivateKey("klucze" + File.separator + user.name, privKeyPassword);

					// decrypt session key
					Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
					rsa.init(Cipher.DECRYPT_MODE, privkey);
					byte[] key = rsa.doFinal(user.encryptedKey);
					SecretKey  sessionKey = new SecretKeySpec(key, "Twofish");

					// prepare cipher
					Cipher cipher;
					if (mode == CipherMode.CFB || mode == CipherMode.OFB) {
						cipher = Cipher.getInstance("Twofish/" + mode.toString() +
								String.valueOf(info.subblockSize) + "/PKCS7Padding");
					} else {
						cipher = Cipher.getInstance("Twofish/" + mode.toString() + "/PKCS7Padding");
					}
					if (mode == CipherMode.ECB) {
						cipher.init(Cipher.DECRYPT_MODE, sessionKey); // ECB doesn't use an IV
					} else {
						cipher.init(Cipher.DECRYPT_MODE, sessionKey, new IvParameterSpec(info.iv));
					}

					// do the real decryption
					try (CipherOutputStream decryptionStream = new CipherOutputStream(outputStream, cipher)) {
						byte[] buffer = new byte[100000]; // 100 kB
						long numBytesProcessed = 0;
						int numBytesRead;
						while ((numBytesRead = inputStream.read(buffer)) >= 0) {
							decryptionStream.write(buffer, 0, numBytesRead);
							numBytesProcessed += numBytesRead;
							updateProgress(numBytesProcessed, filesize);
						}
					}

				}

				return null; // TODO return something else?
			}
		};
	}

	public static HeaderInfo parseHeader(byte[] header) throws IOException, SAXException, NumberFormatException {
		HeaderInfo parsedInfo = new HeaderInfo();
		parsedInfo.users = new ArrayList<>();

		// parse XML
		DocumentBuilder db;
		try {
			db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
		} catch (ParserConfigurationException e) {
			(new Alert(Alert.AlertType.WARNING, "XML parser configuration exception.")).show();
			return parsedInfo;
		}
		Document doc = db.parse(new ByteArrayInputStream(header));
		// see http://stackoverflow.com/questions/13786607/normalization-in-dom-parsing-with-java-how-does-it-work
		doc.getDocumentElement().normalize();

		// get algorithm
		parsedInfo.algorithm = doc.getElementsByTagName("Algorithm").item(0).getFirstChild().getNodeValue();

		// get key size
		parsedInfo.keysize = Integer.parseInt(
				doc.getElementsByTagName("KeySize").item(0).getFirstChild().getNodeValue());

		// get cipher mode of operation
		parsedInfo.cipherMode = CipherMode.valueOf(
				doc.getElementsByTagName("CipherMode").item(0).getFirstChild().getNodeValue());

		// get subblock size
		if (parsedInfo.cipherMode == CipherMode.CFB || parsedInfo.cipherMode == CipherMode.OFB) {
			parsedInfo.subblockSize = Integer.valueOf(
					doc.getElementsByTagName("SegmentSize").item(0).getFirstChild().getNodeValue());
		}

		// get IV
		if (parsedInfo.cipherMode != CipherMode.ECB) {
			String base64IV = doc.getElementsByTagName("IV").item(0).getFirstChild().getNodeValue();
			parsedInfo.iv = Base64.getDecoder().decode(base64IV);
		}

		// get keys nad usernames
		NodeList userNodes = doc.getElementsByTagName("User");
		for (int i = 0; i < userNodes.getLength(); i++) {
			Node userNode = userNodes.item(i);

			if (userNode.getNodeType() == Node.ELEMENT_NODE) {
				Element userElement = (Element) userNode;
				String recipientName = userElement.getElementsByTagName("Name").item(0).getFirstChild().getNodeValue();
				String keyString = userElement.getElementsByTagName("SessionKey").item(0).getFirstChild().getNodeValue();
				byte[] encryptedKey = Base64.getDecoder().decode(keyString);

				User u = new User(recipientName);
				u.encryptedKey = encryptedKey;
				parsedInfo.users.add(u);
			}
		}

		return parsedInfo;
	}

	public static void generateRSAKeypair(String pubFilename, String privFilename, String password) {
		KeyPairGenerator generator;

		try ( PemWriter pubWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream(pubFilename))) ) {
			// set up generator
			generator = KeyPairGenerator.getInstance("RSA", "BC");
			generator.initialize(2048);

			// generate keys
			KeyPair keyPair = generator.generateKeyPair();
			RSAPrivateKey priv = (RSAPrivateKey) keyPair.getPrivate();
			RSAPublicKey pub = (RSAPublicKey) keyPair.getPublic();

			// encrypt the private key
			MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
			byte[] hash = sha256.digest(password.getBytes());   // hash the password
			SecretKey key = new SecretKeySpec(hash, "Twofish"); // use the hash as encryption key, not password
			Cipher cipher = Cipher.getInstance("Twofish/ECB/PKCS7Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] encryptedPrivKey = cipher.doFinal(priv.getEncoded());

			// write the keys
			pubWriter.writeObject(new PemObject("RSA PUBLIC KEY", pub.getEncoded()));
			Files.deleteIfExists(Paths.get(privFilename));
			Path encryptedFile = Files.createFile(Paths.get(privFilename));
			if (encryptedFile != null && encryptedPrivKey != null) {
				Files.write(encryptedFile, encryptedPrivKey);
			} else {
				(new Alert(Alert.AlertType.WARNING, "Cannot save the private key.")).show();
			}

		} catch (NoSuchAlgorithmException e) {
			(new Alert(Alert.AlertType.WARNING, "RSA is not supported. Install Bouncy Castle.")).show();
		} catch (NoSuchProviderException e) {
			(new Alert(Alert.AlertType.WARNING, "Bouncy Castle provider not found. Install Bouncy Castle.")).show();
		} catch (FileNotFoundException e) {
			(new Alert(Alert.AlertType.WARNING, "File \"" + pubFilename + "\" or \"" + privFilename +
					"\" not found.")).show();
		} catch (IOException e) {
			(new Alert(Alert.AlertType.WARNING, "Can't write the \"" + pubFilename + "\" or \"" +
					privFilename + "\" file.")).show();
		} catch (NoSuchPaddingException e) {
			(new Alert(Alert.AlertType.WARNING, "Selected padding is not supported.")).show();
		} catch (BadPaddingException e) {
			(new Alert(Alert.AlertType.WARNING, "Padding is wrong.")).show();
		} catch (IllegalBlockSizeException e) {
			(new Alert(Alert.AlertType.WARNING, "That block size is not supported.")).show();
		} catch (InvalidKeyException e) {
			(new Alert(Alert.AlertType.WARNING, "Twofish encryption key is invalid.")).show();
		}
	}

	public static RSAPublicKey loadPublicKey(String filename) throws IOException, NoSuchProviderException,
			NoSuchAlgorithmException, InvalidKeySpecException {
		PemReader reader = new PemReader(new FileReader(filename));
		PemObject obj = reader.readPemObject();
		byte[] data = obj.getContent();

		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(data);
		KeyFactory factory = KeyFactory.getInstance("RSA", "BC");

		return (RSAPublicKey) factory.generatePublic(pubKeySpec);
	}

	public static RSAPrivateKey loadPrivateKey(String filename, String password) throws IOException {
		// get bytes from encrypted file
		Path encryptedFilePath = Paths.get(filename);
		byte[] encryptedFile = Files.readAllBytes(encryptedFilePath);

		// do the real work
		try {
			// get the hash of password
			MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
			byte[] hash = sha256.digest(password.getBytes());

			// actually decrypt the file
			SecretKey key = new SecretKeySpec(hash, "Twofish");
			Cipher cipher = Cipher.getInstance("Twofish/ECB/PKCS7Padding");
			cipher.init(Cipher.DECRYPT_MODE, key);
			byte[] decryptedFile = cipher.doFinal(encryptedFile);

			// prepare key factory
			PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(decryptedFile);
			KeyFactory factory = KeyFactory.getInstance("RSA", "BC");

			// finally get the key itself
			return (RSAPrivateKey) factory.generatePrivate(privKeySpec);
		} catch (NoSuchAlgorithmException|NoSuchProviderException|NoSuchPaddingException|IllegalBlockSizeException|
				InvalidKeySpecException|InvalidKeyException e) {
			// Either BC or policy file is not installed, user's Java is stupid or there is a bug here or in key generating.
			(new Alert(Alert.AlertType.WARNING, "There was a problem loading the private key. Install Bouncy Castle and policy files. Exception: " + e.getClass().getSimpleName())).show();
		} catch (BadPaddingException e) {
			e.printStackTrace(); // TODO THIS LIKELY MEANS PASSWORD GIVEN WAS BAD. WHAT TO DO?
		}

		// we should never get there
		assert true : "Check the control flow in loadPrivateKey()!";
		return null;
	}

	public static List<Integer> getPossibleSubblockSizes(int keysize) {
		List<Integer> sizes = new ArrayList<>();

		for (int i = 8; i <= keysize; i+=8) {
			sizes.add(i);
		}

		return sizes;
	}

	public static SecretKey generateKey(int keysize) throws NoSuchAlgorithmException {
		KeyGenerator generator = KeyGenerator.getInstance("Twofish");

		generator.init(keysize);

		return generator.generateKey();
	}

	public static byte[] intToByteArray(int i) {
		ByteBuffer bb = ByteBuffer.allocate(4); // Big endian by default.
		bb.putInt(i);
		return bb.array();
	}

	public static int byteArrayToInt(byte[] array) {
		if (array.length != 4)
			return 0;   // TODO perhaps signal error?

		return ByteBuffer.wrap(array).getInt(); // Big endian by default.
	}

	public static byte[] readHeaderBytesFromFile(String filepath) throws IOException {
		try (BufferedInputStream fileStream = new BufferedInputStream(Files.newInputStream(Paths.get(filepath)))) {
			// read header size
			byte[] headerSizeBytes = new byte[4];
			if (fileStream.read(headerSizeBytes) != 4) // we can't even read the size, quit
				throw new IOException("Couldn't read header size from file.");
			int headerSize = Utils.byteArrayToInt(headerSizeBytes);

			// read header bytes
			byte[] header = new byte[headerSize];
			if (fileStream.read(header) != headerSize) // we can't read the header, quit
				throw new IOException("Couldn't read header from file.");

			return header;
		}
	}


}
