package twofish;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.ResourceBundle;

public class Controller implements Initializable{
	// These are lists for ListViews of recipients, for encryption and decryption tab respectively
	ObservableList<User> encryptionRecipients = FXCollections.observableArrayList();
	ObservableList<User> decryptionRecipients = FXCollections.observableArrayList();

	// We need stage for open and save dialogs,
	// so we get it from Main.start(...) trough Controller.setStage(...) method seen somewhere below
	private Stage stage;

	// encryption tab widgets
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

	// decryption tab widgets
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
	void createRSAKeys() {
		Utils.generateRSAKeypair("klucze\\key.pub", "klucze\\key");
	}

	@FXML
	void encrypt() {
		try {
			// read plain
			Path plainFile = Paths.get(selectFileToEncryptTextField.getText());
			byte[] plainData = Files.readAllBytes(plainFile);

			// encrypt
			HeaderInfo info = new HeaderInfo();
			info.cipherMode = (CipherMode) (operationModeChoiceBox.getSelectionModel().getSelectedItem());
			info.users = encryptionRecipients;
			info.algorithm = "Twofish";
			info.keysize = (int) keyLengthChoiceBox.getSelectionModel().getSelectedItem();
			byte[] encryptedData = Utils.encrypt(plainData, info);

			// write encrypted
			Files.deleteIfExists(Paths.get(whereToSaveEncryptedFileTextField.getText()));
			Path encryptedFile = Files.createFile(Paths.get(whereToSaveEncryptedFileTextField.getText()));
			if (encryptedFile != null && encryptedData != null) {
				Files.write(encryptedFile, encryptedData);
			} else {
				Alert alert = new Alert(Alert.AlertType.WARNING, "Cannot encrypt or write file.");
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
			HeaderInfo info = Utils.parseHeader(header);
			assert info.algorithm.equals("Twofish"); // TODO leave it? What do assertions really do?
			decryptionRecipients.addAll(info.users);

			// decrypt
			RSAPrivateKey privkey = Utils.loadPrivateKey("klucze" + File.separator + info.users.get(0).name); // TODO see if key name is OK
			byte[] decryptedData = Utils.decrypt(encryptedData, info.users.get(0).encryptedKey, privkey, info.cipherMode, info.iv);

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
	void addRecipients() {
		try {
			// set up a file chooser
			FileChooser chooser = new FileChooser();
			chooser.setTitle("Wybierz klucz publiczny adresata");
			chooser.setInitialDirectory(new File("klucze"));
			chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Public key", "*.pub"));

			// show chooser and process chosen files TODO find better way to get usernames; this is too hacky
			List<File> files = chooser.showOpenMultipleDialog(stage);
			if (files != null) {
				for (File file : files) {
					String name = file.getName();
					StringBuilder sb = new StringBuilder(name);
					sb.replace(name.lastIndexOf(".pub"), name.lastIndexOf(".pub") + 4, "");
					User user = new User(sb.toString());
					user.pubkey = Utils.loadPublicKey(file.getCanonicalPath());
					if (!encryptionRecipients.contains(user))
						encryptionRecipients.add(user);
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
	void removeRecipients() {
		ObservableList<User> selectedRecipients = editRecipientsListView.getSelectionModel().getSelectedItems();
		encryptionRecipients.removeAll(selectedRecipients);
	}

	// This is a generic method that chooses a file to open/save and sets the appropriate textbox's text.
	// The fact that it's generic made it complicated and less readable, sorry. :)
	@FXML
	void showFileDialog(ActionEvent event) {
		if ( !(event.getSource() instanceof Button) ) { // if it wasn't called by a button, then we have a bug
			System.err.println("showFileDialog is meant to be called only by a button!");
			return;
		}
		Button button = (Button) event.getSource();

		TextField textField;
		String title;
		List<TextField> textFields = new ArrayList<>();

		if (button.equals(selectFileToEncryptButton)) {
			textField = selectFileToEncryptTextField;
			title = "Wybierz plik do zaszyfrowania";

			// all the textfields are ordered for a reason - see below
			textFields.add(textField);
			textFields.add(whereToSaveEncryptedFileTextField);
			textFields.add(selectFileToDecryptTextField);
			textFields.add(whereToSaveDecryptedFileTextField);
		} else if (button.equals(selectFileToDecryptButton)) {
			textField = selectFileToDecryptTextField;
			title = "Wybierz plik do zdeszyfrowania";

			// all the textfields are ordered for a reason - see below
			textFields.add(textField);
			textFields.add(whereToSaveDecryptedFileTextField);
			textFields.add(whereToSaveEncryptedFileTextField);
			textFields.add(selectFileToEncryptTextField);
		} else if (button.equals(whereToSaveEncryptedFileButton)) {
			textField = whereToSaveEncryptedFileTextField;
			title = "Zapisz zaszyfrowany plik jako...";

			// all the textfields are ordered for a reason - see below
			textFields.add(textField);
			textFields.add(selectFileToEncryptTextField);
			textFields.add(selectFileToDecryptTextField);
			textFields.add(whereToSaveDecryptedFileTextField);
		} else  if (button.equals(whereToSaveDecryptedFileButton)) {
			textField = whereToSaveDecryptedFileTextField;
			title = "Zapisz zdeszyfrowany plik jako...";

			// all the textfields are ordered for a reason - see below
			textFields.add(textField);
			textFields.add(selectFileToDecryptTextField);
			textFields.add(selectFileToEncryptTextField);
			textFields.add(whereToSaveEncryptedFileTextField);
		} else {
			System.err.println("You used a showFileDialog from a wrong button!");
			return;
		}

		try {
			// set up a file chooser
			FileChooser chooser = new FileChooser();
			chooser.setTitle(title);
			// This weird code is for user experience - to open a dialog in a likely directory
			// and by likely I mean a directory that is already used somewhere. First we check
			// the textbox next to the button user clicked, then the other textbox on the same tab,
			// then the open file textbox from the other tab and finally the save file textbox
			// from the other tab. (Except for selecting file for decryption, then we swap those
			// 2 last ones.)
			for (TextField tf : textFields) {
				if (!tf.getText().isEmpty()) { // find the first not empty text field that we can get a directory from
					File directory = new File(tf.getText()).getParentFile();
					if (directory != null) {
						chooser.setInitialDirectory(directory);
						break;
					}
				}
			}

			// show chooser and process chosen file
			File file;
			if (button.equals(selectFileToEncryptButton) || button.equals(selectFileToDecryptButton)) { // open file button
				file = chooser.showOpenDialog(stage);
			} else { // save file button
				file = chooser.showSaveDialog(stage);
			}

			if (file != null) {
				String path = file.getCanonicalPath();
				textField.setText(path);
			}
		} catch (IOException e) {
			Alert alert = new Alert(Alert.AlertType.WARNING, "Cannot read or save chosen file.");
		}
	}

	@Override
	public void initialize(URL location, ResourceBundle resources) {
		// Set lists for the ListViews
		editRecipientsListView.setItems(encryptionRecipients);
		showRecipientsListView.setItems(decryptionRecipients);

		// Enable multiple selection
		editRecipientsListView.getSelectionModel().setSelectionMode(SelectionMode.MULTIPLE);
		showRecipientsListView.getSelectionModel().setSelectionMode(SelectionMode.MULTIPLE);

		// Set items for the ChoiceBox
		operationModeChoiceBox.setItems(FXCollections.observableArrayList(CipherMode.values()));
		operationModeChoiceBox.getSelectionModel().selectFirst();

		// Set items for key size ChoiceBox
		keyLengthChoiceBox.setItems(FXCollections.observableArrayList(128, 192, 256));
		keyLengthChoiceBox.getSelectionModel().selectLast();
	}

	public void setStage(Stage stage) {
		this.stage = stage;
	}
}
