package packet.sniffer;

import com.jfoenix.controls.JFXButton;
import java.awt.event.KeyEvent;
import java.net.URL;
import java.util.*;
import java.util.ResourceBundle;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import javafx.scene.input.DragEvent;
import javafx.scene.input.MouseEvent;
import javafx.stage.Stage;
import javafx.util.Callback;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
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
public class MainwindowController implements Initializable {
    
    ArrayList<String> devsList = new ArrayList<String>();
    private void readDevices(){
    List<PcapIf> alldevs = new ArrayList<PcapIf>();  
    StringBuilder errbuf = new StringBuilder(); 
        /*************************************************************************** 
         * First get a list of devices on this system 
         **************************************************************************/  
        int r = Pcap.findAllDevs(alldevs, errbuf);  
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {  
            System.err.printf("Can't read list of devices, error is %s", errbuf  
                .toString());  
            return;  
        }  
  
        System.out.println("Network devices found:");  
  
        int i = 0;  
        for (PcapIf device : alldevs) {  
            String description =  
                (device.getDescription() != null) ? device.getDescription()  
                    : "No description available";  
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
            devsList.add("#"+i+"      "+description);
        }  
  
        PcapIf device = alldevs.get(0); // We know we have atleast 1 device  
        System.out  
            .printf("\nChoosing '%s' on your behalf:\n",  
                (device.getDescription() != null) ? device.getDescription()  
                    : device.getName());  
        
    }

    @FXML
    private TableColumn<inter, String> interfaces;
    @FXML
    private TableView<inter> alldevstable;
    private ArrayList<Integer> trace=new ArrayList<Integer>();
    @FXML
    private JFXButton captureID;
    @FXML
    void capture(ActionEvent event) {
        
    }
    @Override
    public void initialize(URL url, ResourceBundle rb) {
       //readDevices();
       //System.out.println(devsList.get(0));
       interfaces.setCellValueFactory(cellData-> cellData.getValue().str);
       ObservableList<inter> li=FXCollections.observableArrayList();
       for(int i=0 ; i<devsList.size() ; i++){
           li.add(new inter(devsList.get(i)));
       }
       alldevstable.setItems(li);
    }
}
