package twofish;

import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.xml.sax.SAXException;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;

public class Controller implements Initializable{
	// These are lists for ListViews of recipients, for encryption and decryption tab respectively
	ObservableList<User> encryptionRecipients = FXCollections.observableArrayList();
	ObservableList<User> decryptionRecipients = FXCollections.observableArrayList();

	// Will be assigned to when user selects a file to decrypt.
	HeaderInfo decryptionHeaderInfo = null;

	// Tasks that will run in background
	Task decryptionTask;
	Task encryptionTask;

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
		Utils.generateRSAKeypair("klucze\\key.pub", "klucze\\key", "haslo");
	}

	@FXML
	void encrypt() {
		try {
			if (encryptionRecipients.size() <= 0) {
				(new Alert(Alert.AlertType.WARNING, "Add a recipient first.")).show();
				return;
			}
			// read plain
			Path plainFile = Paths.get(selectFileToEncryptTextField.getText());
			byte[] plainData = Files.readAllBytes(plainFile);

			// encrypt
			HeaderInfo info = new HeaderInfo();
			info.cipherMode = (CipherMode) (operationModeChoiceBox.getSelectionModel().getSelectedItem());
			info.users = encryptionRecipients;
			info.algorithm = "Twofish";
			info.keysize = (int) keyLengthChoiceBox.getSelectionModel().getSelectedItem();
			if (info.cipherMode == CipherMode.CFB || info.cipherMode == CipherMode.OFB)
				info.subblockSize = (Integer) subblockLengthChoiceBox.getSelectionModel().getSelectedItem();
			byte[] encryptedData = Utils.encrypt(plainData, info);

			// write encrypted
			Files.deleteIfExists(Paths.get(whereToSaveEncryptedFileTextField.getText()));
			Path encryptedFile = Files.createFile(Paths.get(whereToSaveEncryptedFileTextField.getText()));
			if (encryptedFile != null && encryptedData != null) {
				Files.write(encryptedFile, encryptedData);
			} else {
				(new Alert(Alert.AlertType.WARNING, "Cannot encrypt or write file.")).show();
			}

		} catch (IOException e) {
			(new Alert(Alert.AlertType.WARNING, "Cannot write file.")).show();
		}
	}

	@FXML
	void decrypt() {
		if (decryptionTask != null && decryptionTask.isRunning()) {
			// cancel the decryption task
			decryptionTask.cancel(true);

			decryptButton.setText("Deszyfruj");
			decryptionProgressBar.progressProperty().unbind();
			decryptionProgressBar.setProgress(0);
		} else {
			// prepare decryption task to be run in a new thread
			decryptionTask = Utils.createDecryptTask(
					showRecipientsListView.getSelectionModel().getSelectedItem(),
					decryptionHeaderInfo,
					passwordField.getText(),
					selectFileToDecryptTextField.getText(),
					whereToSaveDecryptedFileTextField.getText()
			);

			decryptionProgressBar.progressProperty().unbind();
			decryptionProgressBar.setProgress(0);
			decryptionProgressBar.progressProperty().bind(decryptionTask.progressProperty());
			decryptButton.setText("Przerwij");
			decryptionTask.runningProperty().addListener(new ChangeListener<Boolean>() {
				@Override
				public void changed(ObservableValue<? extends Boolean> observable, Boolean oldValue, Boolean newValue) {
					if (oldValue == true && newValue == false) { // if it was running, but stopped
						decryptButton.setText("Deszyfruj");
						decryptionProgressBar.progressProperty().unbind();
						decryptionProgressBar.setProgress(0);
					}
				}
			});

			new Thread(decryptionTask).start(); // TODO do we need a handle to this?
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
			(new Alert(Alert.AlertType.WARNING, "RSA algorithm is not supported, install BouncyCastle.")).show();
		} catch (InvalidKeySpecException e) {
			(new Alert(Alert.AlertType.WARNING, "Invalid X.509 KeySpec exception.")).show();
		} catch (NoSuchProviderException e) {
			(new Alert(Alert.AlertType.WARNING, "Install Bouncy Castle.")).show();
		} catch (IOException e) {
			(new Alert(Alert.AlertType.WARNING, "Cannot read the public key.")).show();
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

				if (button.equals(selectFileToDecryptButton)) {
					// display recipients from file header
					try {
						// we need to clear the recipients list because we want to always show recipients for the file
						// currently shown in a selectFileToDecrypt TextField (if file is correct -> has recipients)
						decryptionRecipients.clear();

						HeaderInfo info = Utils.parseHeader(Utils.readHeaderBytesFromFile(path));
						assert info.algorithm.equals("Twofish") : "Algorithm in file header has to be Twofish.";

						decryptionRecipients.addAll(info.users);
						showRecipientsListView.getSelectionModel().selectFirst(); // to always have something selected

						decryptionHeaderInfo = info; // save this as global so we can use it later
					} catch (SAXException | NumberFormatException e) {
						(new Alert(Alert.AlertType.WARNING, "Chosen file's header seems corrupted.")).show();
					} catch (IOException e) {
						(new Alert(Alert.AlertType.WARNING, "Can't process this file. Did you choose a correct " +
								"encrypted file that you have permissions to?")).show();
					}
				}
			}
		} catch (IOException e) {
			(new Alert(Alert.AlertType.WARNING, "Cannot read or save chosen file.")).show();
			e.printStackTrace();
		}
	}

	@Override
	public void initialize(URL location, ResourceBundle resources) {
		// Set lists for the ListViews
		editRecipientsListView.setItems(encryptionRecipients);
		showRecipientsListView.setItems(decryptionRecipients);

		// Enable multiple selection in recipients ListView on encryption tab
		editRecipientsListView.getSelectionModel().setSelectionMode(SelectionMode.MULTIPLE);

		// Set items for cipher operation mode ChoiceBox
		operationModeChoiceBox.setItems(FXCollections.observableArrayList(CipherMode.values()));
		operationModeChoiceBox.getSelectionModel().selectedItemProperty().addListener(new ChangeListener() {
			@Override
			public void changed(ObservableValue observable, Object oldValue, Object newValue) {
				CipherMode cipherMode = (CipherMode) newValue;
				if (cipherMode == CipherMode.CFB || cipherMode == CipherMode.OFB) {
					subblockLengthChoiceBox.setDisable(false);
				} else {
					// disable it since in current cipher operation mode it's not used
					subblockLengthChoiceBox.setDisable(true);
				}
			}
		});
		operationModeChoiceBox.getSelectionModel().select(CipherMode.CBC);

		// Set up key size ChoiceBox
		keyLengthChoiceBox.setItems(FXCollections.observableArrayList(128, 192, 256));
		keyLengthChoiceBox.getSelectionModel().selectedItemProperty().addListener(new ChangeListener() {
			@Override
			public void changed(ObservableValue observable, Object oldValue, Object newValue) {
				int keysize = (int) newValue;
				ObservableList<Integer> sizes = FXCollections.observableArrayList(Utils.getPossibleSubblockSizes(keysize));
				subblockLengthChoiceBox.setItems(sizes);

				// TODO perhaps manually preserve selected item if it's still valid?

				// select last item if nothing is selected
				if (subblockLengthChoiceBox.getSelectionModel().isEmpty())
					subblockLengthChoiceBox.getSelectionModel().selectLast();
			}
		});
		keyLengthChoiceBox.getSelectionModel().selectLast();
	}

	public void setStage(Stage stage) {
		this.stage = stage;
	}
}
