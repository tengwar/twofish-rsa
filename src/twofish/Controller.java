package twofish;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.Parent;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.ResourceBundle;

public class Controller implements Initializable{
	ObservableList<String> encryptionEmails = FXCollections.observableArrayList();
	ObservableList<String> decryptionEmails = FXCollections.observableArrayList();
	private Stage stage;

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
	private ListView<String> editRecipientsListView;
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
	private ListView<String> recipientsListView;
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
	void createRSAKeys() {
		Utils.generateRSAKeypair("klucze\\key.pub", "klucze\\key");
	}

	@FXML
	void encrypt() {
		try {
			// read plain
			Path plainFile = Paths.get(selectFileToEncryptTextField.getText());
			byte[] plainData = Files.readAllBytes(plainFile);

			// write encrypted
			Files.deleteIfExists(Paths.get(whereToSaveEncryptedFileTextField.getText()));
			byte[] encryptedData = Utils.encrypt(plainData, encryptionEmails);

			// write encrypted
			Files.deleteIfExists(Paths.get(whereToSaveEncryptedFileTextField.getText()));
			Path encryptedFile = Files.createFile(Paths.get(whereToSaveEncryptedFileTextField.getText()));
			if (encryptedFile != null && encryptedData != null) {
				Files.write(encryptedFile, encryptedData);
			} else {
				Alert alert = new Alert(Alert.AlertType.WARNING, "Cannot encrypt file.");
			}

		} catch (IOException e) {
			Alert alert = new Alert(Alert.AlertType.WARNING, "Cannot write file.");
		}
	}

	@FXML
	void decrypt() {
		try {
			// read encrypted
			Path encryptedFile = Paths.get(selectFileToDecryptTextField.getText());
			byte[] dataToDecrypt = Files.readAllBytes(encryptedFile);

			// decrypt
			byte[] decryptedData = Utils.decrypt(dataToDecrypt);

			// write decrypted
			Files.deleteIfExists(Paths.get(whereToSaveDecryptedFileTextField.getText()));
			Path decryptedFile = Files.createFile(Paths.get(whereToSaveDecryptedFileTextField.getText()));
			if (decryptedFile != null && decryptedData != null) {
				Files.write(decryptedFile, decryptedData);
			} else {
				Alert alert = new Alert(Alert.AlertType.WARNING, "Cannot decrypt file.");
			}
		} catch (IOException e) {
			Alert alert = new Alert(Alert.AlertType.WARNING, "Cannot read file.");
		}
	}

	@FXML
	void addRecipient() {
		FileChooser chooser = new FileChooser();
		chooser.setTitle("Wybierz klucz publiczny adresata");
		chooser.setInitialDirectory(new File("klucze"));
		chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Public key", "*.pub"));
		List<File> files = chooser.showOpenMultipleDialog(stage);
		if (files != null) {
			for (File file : files) {
				String name = file.getName();
				StringBuilder sb = new StringBuilder(name);
				sb.replace(name.lastIndexOf(".pub"), name.lastIndexOf(".pub") + 4, "");
				encryptionEmails.add(sb.toString()); // TODO prevent duplicates
			}
		}
	}

//	@FXML
//	void removeRecipient() {
//		recipientsListView.getSelectionModel()
//	}

	@Override
	public void initialize(URL location, ResourceBundle resources) {
		editRecipientsListView.setItems(encryptionEmails);
		recipientsListView.setItems(decryptionEmails);
	}

	public void setStage(Stage stage) {
		this.stage = stage;
	}
}
