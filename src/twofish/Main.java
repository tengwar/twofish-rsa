package twofish;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Security;

public class Main extends Application {

	@Override
	public void start(Stage primaryStage) throws Exception{
		Security.addProvider(new BouncyCastleProvider());
		Utils.checkMaxKeyLength("Twofish");

		Path klucze = Paths.get("klucze");
		try {
			if (Files.notExists(klucze))
				Files.createDirectory(klucze);
		} catch (IOException|SecurityException e) {
			System.out.println("Directory klucze is needed by this app.");
		}

//		for (Provider provider : Security.getProviders()) {
//			System.out.println(provider.getName());
//			System.out.println(provider.getInfo());
//			System.out.println();
//		}


//		SecretKey key1 = Utils.generateKey();
//		System.out.println(key1.getAlgorithm());
//		System.out.println(key1.getFormat());
//		System.out.println(key1.toString());
//		System.out.println(key1.getEncoded().length);
//		SecretKey key2 = Utils.generateKey();
//		SecretKey key3 = Utils.generateKey();
//
//		if (Arrays.equals(key1.getEncoded(), key2.getEncoded())) {
//			System.out.println("OK, data correct.");
//		} else {
//			System.out.println("Data incorrect. :(");
//		}
//		if (Arrays.equals(key2.getEncoded(), key3.getEncoded())) {
//			System.out.println("OK, data correct.");
//		} else {
//			System.out.println("Data incorrect. :(");
//		}
//		if (Arrays.equals(key1.getEncoded(), key3.getEncoded())) {
//			System.out.println("OK, data correct.");
//		} else {
//			System.out.println("Data incorrect. :(");
//		}
//		System.out.println(Base64.getEncoder().encodeToString(key1.getEncoded()));
//		System.out.println();
//		System.out.println(Base64.getEncoder().encodeToString(key2.getEncoded()));
//		System.out.println();
//		System.out.println(Base64.getEncoder().encodeToString(key3.getEncoded()));
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
