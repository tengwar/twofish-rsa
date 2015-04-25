package twofish;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.List;
import java.util.ResourceBundle;

public class Controller implements Initializable{
	ObservableList<User> encryptionRecipients = FXCollections.observableArrayList();
	ObservableList<User> decryptionRecipients = FXCollections.observableArrayList();
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
	private ListView<User> editRecipientsListView;
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
	private ListView<User> showRecipientsListView;
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
			byte[] encryptedData = Utils.encrypt(plainData, encryptionRecipients);

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
			byte[] data = Files.readAllBytes(encryptedFile);

			// split encrypted file into header and data
			byte[] header = null;
			byte[] encryptedData = null;
			for (int i = 0; i < data.length; i++) {
				if (data[i] == 0) {
					header = Arrays.copyOfRange(data, 0, i);
					encryptedData = Arrays.copyOfRange(data, i + 1, data.length);
					break;
				}
			}
			if (header == null || encryptedData == null) {
				Alert alert = new Alert(Alert.AlertType.WARNING, "Cannot decrypt file.");
			}

			// process header TODO separate it from decryption and load on file selected
			List<User> users = Utils.parseHeader(header);
			decryptionRecipients.addAll(users);

			// decrypt
			RSAPrivateKey privkey = Utils.loadPrivateKey("klucze" + File.separator + users.get(0).name); // TODO see if key name is OK
			byte[] decryptedData = Utils.decrypt(encryptedData, users.get(0).encryptedKey, privkey);

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
		} catch (ParserConfigurationException e) {
			Alert alert = new Alert(Alert.AlertType.WARNING, "XML parser configuration exception.");
		} catch (SAXException e) {
			Alert alert = new Alert(Alert.AlertType.WARNING, "XML SAX exception.");
		} catch (NoSuchAlgorithmException e) {
			Alert alert = new Alert(Alert.AlertType.WARNING, "RSA algorithm is not supported, install BouncyCastle.");
		} catch (NoSuchProviderException e) {
			Alert alert = new Alert(Alert.AlertType.WARNING, "Install Bouncy Castle.");
		} catch (InvalidKeySpecException e) {
			Alert alert = new Alert(Alert.AlertType.WARNING, "Invalid X.509 KeySpec exception.");
		}
	}

	@FXML
	void addRecipient() {
		try {
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
					User user = new User(sb.toString());
					user.pubkey = Utils.loadPublicKey(file.getCanonicalPath());
					encryptionRecipients.add(user); // TODO prevent duplicates
				}
			}
		} catch (NoSuchAlgorithmException e) {
			Alert alert = new Alert(Alert.AlertType.WARNING, "RSA algorithm is not supported, install BouncyCastle.");
		} catch (InvalidKeySpecException e) {
			Alert alert = new Alert(Alert.AlertType.WARNING, "Invalid X.509 KeySpec exception.");
		} catch (NoSuchProviderException e) {
			Alert alert = new Alert(Alert.AlertType.WARNING, "Install Bouncy Castle.");
		} catch (IOException e) {
			Alert alert = new Alert(Alert.AlertType.WARNING, "Cannot read the public key.");
		}

	}

	@FXML
	void removeRecipient() {
		ObservableList<User> selectedItems = editRecipientsListView.getSelectionModel().getSelectedItems();
		encryptionRecipients.removeAll(selectedItems);
	}

	@Override
	public void initialize(URL location, ResourceBundle resources) {
		// set lists for the ListView
		editRecipientsListView.setItems(encryptionRecipients);
		showRecipientsListView.setItems(decryptionRecipients);

		// enable multiple selection
		editRecipientsListView.getSelectionModel().setSelectionMode(SelectionMode.MULTIPLE);
		showRecipientsListView.getSelectionModel().setSelectionMode(SelectionMode.MULTIPLE);
	}

	public void setStage(Stage stage) {
		this.stage = stage;
	}
}
