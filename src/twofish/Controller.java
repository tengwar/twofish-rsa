package twofish;

import javafx.fxml.FXML;
import javafx.scene.control.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Controller {

	private SecretKey key = null;

	// encryption
	@FXML
	private TextField selectFileToEncryptTextField;
	@FXML
	private Button selectFileToEncryptButton;
	@FXML
	private TextField whereToSaveEncryptedFileTextField;
	@FXML
	private Button whereToSaveEncryptedFileButton;
	@FXML
	private ChoiceBox operationModeChoiceBox;
	@FXML
	private ChoiceBox keyLengthChoiceBox;
	@FXML
	private ChoiceBox subblockLengthChoiceBox;
	@FXML
	private ListView editRecipientsListView;
	@FXML
	private Button addRecipientButton;
	@FXML
	private Button removeRecipientButton;
	@FXML
	private ProgressBar encryptionProgressBar;
	@FXML
	private Button encryptButton;

	// decryption
	@FXML
	private TextField selectFileToDecryptTextField;
	@FXML
	private Button selectFileToDecryptButton;
	@FXML
	private TextField whereToSaveDecryptedFileTextField;
	@FXML
	private Button whereToSaveDecryptedFileButton;
	@FXML
	private ListView recipientsListView;
	@FXML
	private PasswordField passwordField;
	@FXML
	private Button showPasswordButton;
	@FXML
	private ProgressBar decryptionProgressBar;
	@FXML
	private Button decryptButton;

	@FXML
	void printText(){
		System.out.println("top lel");
	}

	@FXML
	void encrypt(){
		try {
			// read plain
			Path plainFile = Paths.get(selectFileToEncryptTextField.getText());
			byte[] plainData = Files.readAllBytes(plainFile);
			key = Utils.generateKey(); // TODO proper key generation and saving

			// encrypt
			byte[] encryptedData = Utils.twofishEncrypt(plainData, key);

			// write encrypted
			Files.deleteIfExists(Paths.get(whereToSaveEncryptedFileTextField.getText()));
			Path encryptedFile = Files.createFile(Paths.get(whereToSaveEncryptedFileTextField.getText()));
			Files.write(encryptedFile, encryptedData);
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Twofish algorithm is not supported, install BouncyCastle.");
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			System.out.println("Selected padding is not supported.");
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		}
	}

	@FXML
	void decrypt(){
		if (key != null) {
			try {
				// read encrypted
				Path encryptedFile = Paths.get(selectFileToDecryptTextField.getText());
				byte[] dataToDecrypt = Files.readAllBytes(encryptedFile);

				// decrypt
				byte[] decryptedData = Utils.twofishDecrypt(dataToDecrypt, key);

				// write decrypted
				Files.deleteIfExists(Paths.get(whereToSaveDecryptedFileTextField.getText()));
				Path decryptedFile = Files.createFile(Paths.get(whereToSaveDecryptedFileTextField.getText()));
				Files.write(decryptedFile, decryptedData);
			} catch (NoSuchAlgorithmException e) {
				System.out.println("Twofish algorithm is not supported, install BouncyCastle.");
			} catch (IOException e) {
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				e.printStackTrace();
			} catch (BadPaddingException e) {
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				System.out.println("Selected padding is not supported.");
			} catch (IllegalBlockSizeException e) {
				e.printStackTrace();
			}
		} else {
			System.out.println("Select a key first.");
		}

	}
}
