package twofish;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Main extends Application {

	@Override
	public void start(Stage primaryStage) throws Exception{
		Security.addProvider(new BouncyCastleProvider());
		Utils.checkMaxKeyLength("Twofish");

		Parent root = FXMLLoader.load(getClass().getResource("twofish.fxml"));
		primaryStage.setTitle("Twofish");
		primaryStage.setScene(new Scene(root));
		primaryStage.show();
	}


	public static void main(String[] args) {
		launch(args);
	}
}
