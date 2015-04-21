package twofish;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.SecretKey;

public class Main extends Application {

	@Override
	public void start(Stage primaryStage) throws Exception{
		Security.addProvider(new BouncyCastleProvider());
		Utils.checkMaxKeyLength("Twofish");

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

		Parent root = FXMLLoader.load(getClass().getResource("twofish.fxml"));
		primaryStage.setTitle("Twofish");
		primaryStage.setScene(new Scene(root));
		primaryStage.show();
	}


	public static void main(String[] args) {
		launch(args);
	}
}
