package twofish;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

public class Main extends Application {

	@Override
	public void start(Stage primaryStage) throws Exception{
		Security.addProvider(new BouncyCastleProvider());
		try {
			System.out.println("The allowed key length for Twofish is: " + Cipher.getMaxAllowedKeyLength("Twofish"));
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Twofish algorithm is not supported, install BouncyCastle.");
		}

		Path klucze = Paths.get("klucze");
		try {
			if (Files.notExists(klucze))
				Files.createDirectory(klucze);
		} catch (IOException|SecurityException e) {
			System.err.println("Directory klucze is needed by this app.");
		}

//		// list providers for debug
//		for (Provider provider : Security.getProviders()) {
//			System.out.println(provider.getName());
//			System.out.println(provider.getInfo());
//			System.out.println();
//		}

		final FXMLLoader loader = new FXMLLoader(getClass().getResource("twofish.fxml"));
		final Parent root = (Parent) loader.load();
		((Controller) loader.getController()).setStage(primaryStage);
		primaryStage.setTitle("Twofish");
		primaryStage.setScene(new Scene(root));
		primaryStage.show();
	}


	public static void main(String[] args) {
		launch(args);
	}
}
