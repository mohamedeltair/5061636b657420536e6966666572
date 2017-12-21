package packet.sniffer;

import com.jfoenix.controls.JFXButton;
import java.awt.event.KeyEvent;
import java.net.URL;
import java.util.*;
import java.util.ResourceBundle;
import javafx.application.Platform;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.input.DragEvent;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import javafx.stage.WindowEvent;
import javafx.util.Callback;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JHeaderPool;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

/**
 * FXML Controller class
 *
 * @author ahmedsalah
 */
class inter{
    SimpleStringProperty str;

    public inter() {
        this(null);
    }

    public inter(String str) {
        this.str=new SimpleStringProperty(str);
    }
    
}


public class MainwindowController implements Initializable{
    
    ArrayList<String> devsList = new ArrayList<String>();
    List<PcapIf> alldevs;  
    StringBuilder errbuf; 
    ObservableList<inter> li;
    @FXML
    private TableColumn<inter, String> interfaces;
    @FXML
    private TableView<inter> alldevstable;
    private ArrayList<Integer> trace=new ArrayList<Integer>();
    @FXML
    private JFXButton captureID;
    @FXML
    void capture(ActionEvent event) {
        Main_Controller.stopBtnIsClicked = false;
        int index = alldevstable.getSelectionModel().getSelectedIndex();
        if(index != -1){
        Stage stage = (Stage)captureID.getScene().getWindow();
        FXMLLoader loader = new FXMLLoader();
        loader.setLocation(getClass().getResource("PS_View.fxml"));
         try {
             loader.load();       
        } catch(Exception e) {
           e.printStackTrace();
          }
        Main_Controller d = loader.getController();
        PacketsHandler ph = new PacketsHandler(index, alldevs, errbuf, d);
        ph.start();
        Stage stage2=(Stage)((Node)event.getSource()).getScene().getWindow();
        Parent root1 = loader.getRoot();
        Scene scene1 = new Scene(root1);
        stage.setOnHiding(new EventHandler<WindowEvent>() {

         @Override
         public void handle(WindowEvent event) {
             Platform.runLater(new Runnable() {

                 @Override
                 public void run() {
                     Thread.currentThread().interrupt();
                     System.exit(0);
                 }
             });
         }
     });
        stage2.setScene(scene1);
        stage2.show();
        stage2.setResizable(false);
        }
        else{
            try{
            Alert alert = new Alert(AlertType.ERROR);
            alert.setTitle("Error");
            alert.setHeaderText("Woops , Something went wrong :(");
            alert.setContentText("Please select an interface from the list or click on refresh if nothing is displayed");
            alert.showAndWait();
        }
        catch(Exception e){
            System.out.println(e.toString());
        }
        }
    }
    
    private void readDevices(){
        alldevs = new ArrayList<PcapIf>();  
        errbuf = new StringBuilder(); 
        /*************************************************************************** 
         * First get a list of devices on this system 
         **************************************************************************/  
        int r = Pcap.findAllDevs(alldevs, errbuf);  
  
        int i = 0;  
        for (PcapIf device : alldevs) {  
            String description =  
                (device.getDescription() != null) ? device.getDescription()  
                    : "No description available";  
            devsList.add("#"+ ++i +"      "+description);
        }  
        
    }
    
    
    public void fillTable(){
       readDevices();
       li=FXCollections.observableArrayList();
       for(int i=0 ; i<devsList.size() ; i++) li.add(new inter(devsList.get(i)));
       alldevstable.setItems(li);
    }
    
    public void emptyTable(){
        devsList.clear();
        li.clear();
    }
    
    @Override
    public void initialize(URL url, ResourceBundle rb) {
       interfaces.setCellValueFactory(cellData-> cellData.getValue().str);
       fillTable();
    }
    
    
    @FXML
    private void refresh(){
        alldevstable.refresh();
        emptyTable();
        fillTable();
        alldevstable.refresh();
    }

}
