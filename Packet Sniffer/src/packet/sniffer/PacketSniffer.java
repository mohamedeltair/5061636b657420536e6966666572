package packet.sniffer;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class PacketSniffer extends Application {
    Stage window;
    Scene mainView , interfacesView;
    @Override
    public void start(Stage primaryStage) throws Exception {
        window = primaryStage;
        window.setResizable(false);
        window.setMaxWidth(1070);
        window.setMaxHeight(850);
        window.setTitle("Mini Wireshark");
        Parent root = FXMLLoader.load(getClass().getResource("mainwindow1.fxml"));
        Scene mainView = new Scene(root);
        window.setScene(mainView);
        window.show();
    }

    
    public static void main(String[] args) {
        //Setup the program as JavaFX application and call start method
        launch(args);
    }
    
}
