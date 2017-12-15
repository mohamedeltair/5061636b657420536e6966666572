package packet.sniffer;

import com.jfoenix.controls.JFXTextArea;
import java.net.URL;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.ResourceBundle;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.stage.Stage;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

public class Main_Controller implements Initializable {  
    ObservableList<Packet> pcks=FXCollections.observableArrayList();
    @FXML
    private TableView<Packet> packets;
    @FXML
    private TableColumn<Packet, String> numC;

    @FXML
    private TableColumn<Packet, String> timeC;

    @FXML
    private TableColumn<Packet, String> sourceC;

    @FXML
    private TableColumn<Packet, String> destC;

    @FXML
    private TableColumn<Packet, String> protC;

    @FXML
    private TableColumn<Packet, String> lengthC;

@FXML
    private JFXTextArea ethernet;

    @FXML
    private JFXTextArea arp;

    @FXML
    private JFXTextArea ICMP;

    @FXML
    private JFXTextArea IP4;

    @FXML
    private JFXTextArea IP6;

    @FXML
    private JFXTextArea tcp;

    @FXML
    private JFXTextArea udp;

    @FXML
    private JFXTextArea http;

    @FXML
    private JFXTextArea phexa;
    
    @FXML
    private TableColumn<Packet, String> infoC;

    public void showInterfacesWindow(){
        try{
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

    @Override
    public void initialize(URL location, ResourceBundle resources) {
         numC.setCellValueFactory(cellData->cellData.getValue().no);
         destC.setCellValueFactory(cellData->cellData.getValue().dest);
         infoC.setCellValueFactory(cellData->cellData.getValue().info);
         sourceC.setCellValueFactory(cellData->cellData.getValue().source);
         lengthC.setCellValueFactory(cellData->cellData.getValue().length);
         protC.setCellValueFactory(cellData->cellData.getValue().protocol);
         timeC.setCellValueFactory(cellData->cellData.getValue().time);
                packets.getSelectionModel().selectedItemProperty().addListener((obs, oldSelection, newSelection) -> {
                    int ind=packets.getSelectionModel().getSelectedIndex();
                      
                });
    }
    public void addRow(Packet pck){
        pcks.add(pck);
        packets.setItems(pcks);
    }
    
}