package packetsniffer;

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
    List<PcapIf> alldevs = new ArrayList<PcapIf>();  
    StringBuilder errbuf = new StringBuilder(); 
    private void readDevices(){
        alldevs = new ArrayList<PcapIf>();  
        errbuf = new StringBuilder(); 
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
        int index = alldevstable.getSelectionModel().getSelectedIndex();
        Stage stage = (Stage) captureID.getScene().getWindow();
        // do what you have to do
        stage.close();
        PcapIf device = alldevs.get(index);
        int snaplen = 64 * 1024;           // Capture all packets, no trucation  
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
        int timeout = 10 * 1000;           // 10 seconds in millis  
        Pcap pcap =  
            Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);  
  
        if (pcap == null) {  
            System.err.printf("Error while opening device for capture: "  
                + errbuf.toString());  
            return;  
        }  
  
        /*************************************************************************** 
         * Third we create a packet handler which will receive packets from the 
         * libpcap loop. 
         **************************************************************************/  
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {  
  
            public void nextPacket(PcapPacket packet, String user) {  
                System.out.printf("Received packet at %s caplen=%-4d len=%-4d %s\n",  
                    new Date(packet.getCaptureHeader().timestampInMillis()),   
                    packet.getCaptureHeader().caplen(),  // Length actually captured  
                    packet.getCaptureHeader().wirelen(), // Original length   
                    user                                 // User supplied object  
                    );
                /*Tcp tcp = packet.getHeader(new Tcp());
                System.out.println("tcp: "+tcp);
                Http http = packet.getHeader(new Http());
                System.out.println("http: "+http);
                Udp udp = packet.getHeader(new Udp());
                System.out.println("udp: "+udp);
                Ip4 ip4 = packet.getHeader(new Ip4());
                System.out.println("ip4: "+ip4);
                System.out.println("source, dest: " + getIP(ip4.source()) +", "+
                getIP(ip4.destination()));
                Ethernet ethernet = packet.getHeader(new Ethernet());
                System.out.println("ethernet: "+ethernet);
                System.out.println("hexa: " + packet.toHexdump());*/
            }  
        }; 
        pcap.loop(pcap.LOOP_INFINATE, jpacketHandler, "");  
  
        /*************************************************************************** 
         * Last thing to do is close the pcap handle 
         **************************************************************************/  
        pcap.close();  
    }
    @Override
    public void initialize(URL url, ResourceBundle rb) {
       readDevices();
       System.out.println(devsList.get(0));
       interfaces.setCellValueFactory(cellData-> cellData.getValue().str);
       ObservableList<inter> li=FXCollections.observableArrayList();
       for(int i=0 ; i<devsList.size() ; i++){
           li.add(new inter(devsList.get(i)));
       }
       alldevstable.setItems(li);
    }
}
