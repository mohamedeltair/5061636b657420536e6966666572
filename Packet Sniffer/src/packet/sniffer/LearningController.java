/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package packet.sniffer;

import com.jfoenix.controls.JFXButton;
import java.io.File;
import java.net.URL;
import java.util.ResourceBundle;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

/**
 * FXML Controller class
 *
 * @author ahmedsalah
 */
public class LearningController implements Initializable {

    @FXML
    private TableView<Learned> result;

    @FXML
    private TableColumn<Learned, String> num,recog, act, accCol;

    @Override
    public void initialize(URL url, ResourceBundle rb) {
        num.setCellValueFactory(cellData-> cellData.getValue().number);
        recog.setCellValueFactory(cellData-> cellData.getValue().recognised);
        act.setCellValueFactory(cellData-> cellData.getValue().actual);
        accCol.setCellValueFactory(cellData-> cellData.getValue().acc);
    }    
    public void filltable(ObservableList<Learned> input){
        result.setItems(input);
    }
    @FXML
    void learn(ActionEvent event) {
        FileChooser fc = new FileChooser();
       fc.setTitle("Select file to learn from");

        File selectedFile = fc.showOpenDialog(null);
        String fileName = selectedFile.getAbsolutePath();
    }

    @FXML
    void recognise(ActionEvent event) {
        FileChooser fc = new FileChooser();
       fc.setTitle("Select file to be recognised");

        File selectedFile = fc.showOpenDialog(null);
        String fileName = selectedFile.getAbsolutePath();
    }
    @FXML
    void back(ActionEvent event) {
        try{
            Stage stage=(Stage)result.getScene().getWindow();
            stage.close();
            Stage window = new Stage();
            window.setTitle("Devices List");
            Parent root = FXMLLoader.load(getClass().getResource("mainwindow1.fxml"));
            Scene interfacesView = new Scene(root);
            window.setScene(interfacesView);
            window.show();
        }
        catch(Exception e){
            System.out.println(e.toString());
        }
    }
}
