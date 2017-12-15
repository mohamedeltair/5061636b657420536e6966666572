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
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
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

class Utilities {
    public static int toUnsignedByte(byte val) {
        return (int)(val & 0x000000FF);
    }
    public static String getIP(byte[] arr) {
        return toUnsignedByte(arr[0])+"."+toUnsignedByte(arr[1])+"."+toUnsignedByte(arr[2])+"."+toUnsignedByte(arr[3]);
    }
    public static Http getHttp(PcapPacket packet) {
        return packet.getHeader(new Http());   
    }
    public static Tcp getTcp(PcapPacket packet) {
        return packet.getHeader(new Tcp());   
    }
    public static Udp getUdp(PcapPacket packet) {
        return packet.getHeader(new Udp());   
    }
    public static Ip4 getIp4(PcapPacket packet) {
        return packet.getHeader(new Ip4());   
    }
    public static Ip6 getIp6(PcapPacket packet) {
        return packet.getHeader(new Ip6());   
    }
    public static Icmp getIcmp(PcapPacket packet) {
        return packet.getHeader(new Icmp());   
    }
    public static Arp getArp(PcapPacket packet) {
        return packet.getHeader(new Arp());   
    }
    public static Ethernet getEthernet(PcapPacket packet) {
        return packet.getHeader(new Ethernet());   
    }
    public static String getHexa(PcapPacket packet) {
        return packet.toHexdump();
    }
}



class PacketsHandler extends Thread {
    private int index;
    List<PcapIf> alldevs;  
    StringBuilder errbuf; 
    Main_Controller d;
    int count=1;
    public PacketsHandler(int index, List<PcapIf> alldevs, StringBuilder errbuf, Main_Controller d) {
        this.index = index;
        this.alldevs = alldevs;
        this.errbuf = errbuf;
        this.d = d;
    }
    @Override
    public void run() {
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
        
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {  
  
            public void nextPacket(PcapPacket packet, String user) {  
                System.out.printf("Received packet at %s caplen=%-4d len=%-4d %s\n",  
                    new Date(packet.getCaptureHeader().timestampInMillis()),   
                    packet.getCaptureHeader().caplen(),  
                    packet.getCaptureHeader().wirelen(),  
                    user                                  
                    );
                Ip4 ip4 = Utilities.getIp4(packet);
                String source = Utilities.getIP(ip4.source());
                String destination = Utilities.getIP(ip4.destination());
                d.addRow(new Packet((count++)+"", "", source, destination, "", "", ""));
            }  
        };  
        pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, "jNetPcap rocks!");   
        pcap.close();
    }
}
public class MainwindowController implements Initializable {
    
    ArrayList<String> devsList = new ArrayList<String>();
    List<PcapIf> alldevs;  
    StringBuilder errbuf; 
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
        stage2.setScene(scene1);
        stage2.show();
        stage2.setResizable(false);
    }
    @Override
    public void initialize(URL url, ResourceBundle rb) {
       readDevices();
       interfaces.setCellValueFactory(cellData-> cellData.getValue().str);
       ObservableList<inter> li=FXCollections.observableArrayList();
       for(int i=0 ; i<devsList.size() ; i++){
           li.add(new inter(devsList.get(i)));
       }
       alldevstable.setItems(li);
    }
}
