package twofish;

/**
 * Created by Grzegorz on 2015-04-19.
 */

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
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
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
	public static byte[] encrypt(byte[] data, List<User> users) {
		byte[] file = null;
		try {
			// generate key
			SecretKey sessionKey = generateKey();

			// prepare cipher
			Cipher cipher = Cipher.getInstance("Twofish/ECB/PKCS5Padding");
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
			algorithm.appendChild(doc.createTextNode("Twofish"));
			root.appendChild(algorithm);

			// key size node
			Element keysize = doc.createElement("KeySize");
			keysize.appendChild(doc.createTextNode(String.valueOf(sessionKey.getEncoded().length * 8)));
			root.appendChild(keysize);

			// TODO subblock size

			// cipher mode node
			Element mode = doc.createElement("CipherMode");
			mode.appendChild(doc.createTextNode("ECB")); // TODO use real value
			root.appendChild(mode);

			// IV node
			if (cipher.getIV() != null) {
				Element iv = doc.createElement("IV");
				iv.appendChild(doc.createTextNode(Base64.getEncoder().encodeToString(cipher.getIV())));
				root.appendChild(iv);
			}

			// users node
			Element usersNode = doc.createElement("ApprovedUsers");
			root.appendChild(usersNode);

			// add users TODO use actual users
			for (User user : users) {
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
			DOMSource source = new DOMSource(doc);
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			StreamResult result = new StreamResult(baos);
			// Output to console for testing
			//StreamResult result = new StreamResult(System.out);
			// Output to file
			//StreamResult result = new StreamResult(new File(filePath));

			transformer.transform(source, result);

			baos.write(new byte[1]); // a zero byte separating xml and binary; array is guaranteed to be zeroed when created
			baos.write(encrypted);
			file = baos.toByteArray();

		} catch (ParserConfigurationException e) {
			Alert alert = new Alert(Alert.AlertType.WARNING, "XML parser configuration exception.");
		} catch (TransformerConfigurationException e) {
			Alert alert = new Alert(Alert.AlertType.WARNING, "XML transformer configuration exception.");
		} catch (TransformerException e) {
			Alert alert = new Alert(Alert.AlertType.WARNING, "XML transformer exception.");
		} catch (InvalidKeyException e) {
			Alert alert = new Alert(Alert.AlertType.WARNING, "Twofish encryption key is invalid."); // TODO is this OK?
		} catch (NoSuchAlgorithmException e) {
			Alert alert = new Alert(Alert.AlertType.WARNING, "Twofish algorithm is not supported, install BouncyCastle.");
		} catch (NoSuchPaddingException e) {
			Alert alert = new Alert(Alert.AlertType.WARNING, "Selected padding is not supported.");
		} catch (BadPaddingException e) {
			Alert alert = new Alert(Alert.AlertType.WARNING, "Padding is wrong.");
		} catch (IllegalBlockSizeException e) {
			Alert alert = new Alert(Alert.AlertType.WARNING, "That block size is not supported.");
		} catch (IOException e) {
			Alert alert = new Alert(Alert.AlertType.WARNING, "ByteArrayOutputStream IO exception. Shouldn't happen.");
		}

		return file;
	}

	public static byte[] decrypt(byte[] encryptedData, byte[] encryptedSessionKey, RSAPrivateKey privkey) {
		byte[] decrypted = null;
		try {
			// decrypt session key
			SecretKey sessionKey = null;
			Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
			rsa.init(Cipher.DECRYPT_MODE, privkey);
			byte[] key = rsa.doFinal(encryptedSessionKey);
			sessionKey = new SecretKeySpec(key, "Twofish");

			// prepare cipher
			Cipher cipher = Cipher.getInstance("Twofish/ECB/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, sessionKey);

			// decrypt
			decrypted = cipher.doFinal(encryptedData);

		} catch (IllegalBlockSizeException e) {
			Alert alert = new Alert(Alert.AlertType.WARNING, "That block size is not supported.");
		} catch (InvalidKeyException e) {
			// Alert alert = new Alert(Alert.AlertType.WARNING, "Twofish encryption key is invalid."); // TODO is this OK?
		} catch (BadPaddingException e) {
			Alert alert = new Alert(Alert.AlertType.WARNING, "Padding is wrong.");
		} catch (NoSuchAlgorithmException e) {
			Alert alert = new Alert(Alert.AlertType.WARNING, "Twofish algorithm is not supported, install BouncyCastle.");
		} catch (NoSuchPaddingException e) {
			Alert alert = new Alert(Alert.AlertType.WARNING, "Selected padding is not supported.");
		}

		return decrypted;
	}

	public static List<User> parseHeader(byte[] header) throws ParserConfigurationException, IOException, SAXException {
		List<User> users = new ArrayList<>();

		// parse XML
		DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
		Document doc = db.parse(new ByteArrayInputStream(header));
		// see http://stackoverflow.com/questions/13786607/normalization-in-dom-parsing-with-java-how-does-it-work
		doc.getDocumentElement().normalize();

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
				users.add(u);
			}
		}

		return users;
	}

	public static void generateRSAKeypair(String pubFilename, String privFilename) {
		KeyPairGenerator generator = null;

		try ( PemWriter pubWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream(pubFilename)));
				PemWriter privWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream(privFilename))) ) {
			// set up generator
			generator = KeyPairGenerator.getInstance("RSA", "BC");
			generator.initialize(2048);

			// generate keys
			KeyPair keyPair = generator.generateKeyPair();
			RSAPrivateKey priv = (RSAPrivateKey) keyPair.getPrivate();
			RSAPublicKey pub = (RSAPublicKey) keyPair.getPublic();

			// write the keys
			pubWriter.writeObject(new PemObject("RSA PUBLIC KEY", pub.getEncoded()));
			privWriter.writeObject(new PemObject("RSA PRIVATE KEY", priv.getEncoded()));

		} catch (NoSuchAlgorithmException e) {
			Alert alert = new Alert(Alert.AlertType.WARNING, "RSA is not supported. Install Bouncy Castle.");
		} catch (NoSuchProviderException e) {
			Alert alert = new Alert(Alert.AlertType.WARNING, "Bouncy Castle provider not found. Install Bouncy Castle.");
		} catch (FileNotFoundException e) {
			Alert alert = new Alert(Alert.AlertType.WARNING, "File \"" + pubFilename + "\" or \"" + privFilename + "\" not found.");
		} catch (IOException e) {
			Alert alert = new Alert(Alert.AlertType.WARNING, "Can't write the \"\" + pubFilename + \"\\\" or \\\"\" + privFilename + \"\" file.");
		}
	}

	public static RSAPublicKey loadPublicKey(String filename) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
		PemReader reader = new PemReader(new FileReader(filename));
		PemObject obj = reader.readPemObject();
		byte[] data = obj.getContent();

		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(data);
		KeyFactory factory = KeyFactory.getInstance("RSA", "BC");

		return (RSAPublicKey) factory.generatePublic(pubKeySpec);
	}

	public static RSAPrivateKey loadPrivateKey(String filename) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
		PemReader reader = new PemReader(new FileReader(filename));
		PemObject obj = reader.readPemObject();
		byte[] data = obj.getContent();

		PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(data);
		KeyFactory factory = KeyFactory.getInstance("RSA", "BC");

		return (RSAPrivateKey) factory.generatePrivate(privKeySpec);
	}

	public static SecretKey generateKey() throws NoSuchAlgorithmException {
		SecureRandom rand = new SecureRandom();
		KeyGenerator generator = KeyGenerator.getInstance("Twofish");

		generator.init(rand);

		return generator.generateKey();
	}
}
