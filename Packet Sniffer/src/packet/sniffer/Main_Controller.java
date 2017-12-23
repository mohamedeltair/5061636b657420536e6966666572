package packet.sniffer;

import com.jfoenix.controls.JFXTextArea;
import com.jfoenix.controls.JFXTextField;
import java.awt.Desktop;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.ResourceBundle;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
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
import javafx.scene.control.Hyperlink;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.*;
import static packet.sniffer.PacketsHandler.pcap;

public class Main_Controller implements Initializable {  
    ObservableList<Packet> pcks=FXCollections.observableArrayList();
    ObservableList<Packet> newPcks;
    ChangeListener<Object> listener = new ChangeListener() {
        @Override
        public void changed(ObservableValue observable, Object oldValue, Object newValue) {
            try {
                modifyData();
            }
            catch(Exception e ){
                
            }
        }
    };
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
    private JFXTextField filter;
    @FXML
    Hyperlink hyperlink;
    @FXML
    private TableColumn<Packet, String> infoC;
    
    public static boolean stopBtnIsClicked = false;

    public void showInterfacesWindow(ActionEvent even){
        try{
            Parent root = FXMLLoader.load(getClass().getResource("mainwindow1.fxml"));
        Scene scene = new Scene(root);
        Stage stage=(Stage)packets.getScene().getWindow();
        stage.setScene(scene);
        stage.setTitle("Devices List");
        stage.show();
        }
        catch(Exception e){
            System.out.println(e.toString());
        }
    }
    
     public void Stop()
    {
        if(!stopBtnIsClicked) pcap.breakloop();
        stopBtnIsClicked = true;
    }
     
     public void Save()
     {
        try {
            FileChooser fc = new FileChooser();
            fc.setTitle("Select file location");
            
            File selectedFile = fc.showSaveDialog(null);
            String ofile = selectedFile.getCanonicalPath();
            if(!ofile.endsWith(".pcap")){
                ofile+=".pcap";
            }
            PcapDumper dumper = pcap.dumpOpen(ofile);
            
            for(int i =0; i<PacketsHandler.packets.size(); i++)
            {
                dumper.dump(PacketsHandler.packets.get(i).getCaptureHeader(),PacketsHandler.packets.get(i));
            }   
        } catch (IOException ex) {
            System.out.println("save exception");
        }
        catch(Exception e){}
     }
    
    public void Load() {
        try{
          
        FileChooser fc = new FileChooser();
       fc.setTitle("Select pcap file");

        File selectedFile = fc.showOpenDialog(null);
        String fileName = selectedFile.getAbsolutePath();
if (selectedFile != null) {
            stopBtnIsClicked = true;
          pcks.clear();
          PacketsHandler.packets.clear();
    
StringBuilder errbuf = new StringBuilder();  
    Pcap pcap = Pcap.openOffline(fileName,errbuf);
        //2-check if all OK
        if (pcap == null) {  
          System.err.printf("Error while opening device for capture: "  
    + errbuf.toString()); 
            System.out.println("null");
        }
        else {System.out.println("correctPCAP");}
        
           PacketsHandler.packets.clear();
        
        //3-create packet handler
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
               int count =1;
            @Override
            
            public void nextPacket(PcapPacket packet, String user) {
             
            
                PacketsHandler.packets.add(packet);
                
                System.out.printf("Received at %s caplen=%-4d len=%-4d %s\n",   
                    new Date(packet.getCaptureHeader().timestampInMillis()),   
                    packet.getCaptureHeader().caplen(), // Length actually captured
                    packet.getCaptureHeader().wirelen(), // Original length  
                    user // User supplied object  
                    );  
                /****************REDUNDANT CODE***************************/
                Ip4 ip4 = Utilities.getIp4(packet);
                
                Ip6 ip6 = Utilities.getIp6(packet);
                Ethernet ethernet = Utilities.getEthernet(packet);
                String source = "", destination = "";
                if(ip4!=null) {
                    source = FormatUtils.ip(ip4.source());
                    destination = FormatUtils.ip(ip4.destination());
                }
                else if(ip6!=null) {
                   
                    source = Utilities.ip6ToString(ip6.source());
                    destination = Utilities.ip6ToString(ip6.destination());
                }
                else if(ethernet != null) {
                    source = FormatUtils.mac(ethernet.source());
                    destination = FormatUtils.mac(ethernet.destination());
                }
                else {
                    source = "unknown";
                    destination = "unknown";
                }
                ArrayList<JHeader> headers = Utilities.getHeaders(packet);
                int last = headers.get(headers.size()-1).getName().equals("Html")?headers.size()-2:headers.size()-1;
                String all = "";
                for(int i=0; i<=last; i++) {
                    all+=headers.get(i).getName();
                    if(i!=last)
                        all+=", ";
                }
                
                /*********************************REDUNDANT CODE END**********************************/
                
             Main_Controller.this.addRow(new Packet((count++)+"", new Date(packet.getCaptureHeader().timestampInMillis()).toString(), source, destination,
                        headers.get(last).getName(), packet.getCaptureHeader().wirelen()+"", "Protocols involved: "+all));
           
              
            }  
        };
        
        try {
           pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, "");
        }
        catch(Exception ex)
        {
            System.out.println("END OF FILE");
        }
        
      
        
}

        }
        catch (Exception e){}
          
    }
     
 
    public String check(Object o){
        if(o == null) return "Protocol doesn't exist";
        return o.toString();
    }

    synchronized public void modifyData() {
        Packet p = packets.getSelectionModel().getSelectedItem();
        if(p==null)
            return;
        int ind=Integer.parseInt(p.no.getValue())-1;
        if(ind < 0 || ind >= PacketsHandler.packets.size())
            return;
        
        ethernet.setText(check((Utilities.getEthernet(PacketsHandler.packets.get(ind)))));
        arp.setText(check(Utilities.getArp(PacketsHandler.packets.get(ind))));
        ICMP.setText(check(Utilities.getIcmp(PacketsHandler.packets.get(ind))));
        IP4.setText(check(Utilities.getIp4(PacketsHandler.packets.get(ind))));
        IP6.setText(Utilities.ip6Info(Utilities.getIp6(PacketsHandler.packets.get(ind))));
        tcp.setText(check(Utilities.getTcp(PacketsHandler.packets.get(ind))));
        udp.setText(check(Utilities.getUdp(PacketsHandler.packets.get(ind))));
        http.setText(check(Utilities.getHttp(PacketsHandler.packets.get(ind))));
        String html = check(Utilities.getHtml(PacketsHandler.packets.get(ind)));
        if(!html.equals("Protocol doesn't exist")) {
            http.setText(http.getText()+"\n\nHtml:\n"+html);
        }
        phexa.setText(Utilities.getHexa(PacketsHandler.packets.get(ind)));
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
        packets.getSelectionModel().selectedItemProperty().addListener(listener);
        filter.textProperty().addListener((observable, oldValue, newValue) -> {
            addRow(null);
        });
        hyperlink.setOnAction(new EventHandler<ActionEvent>() {

            @Override
            public void handle(ActionEvent event) {
                try {
                    Desktop.getDesktop().browse(new URI("https://github.com/mohamedeltair/5061636b657420536e6966666572/graphs/contributors"));
                } catch (Exception ex) {
                }
            }
        });
    }
    synchronized public void addRow(Packet pck){
        try {
            packets.getSelectionModel().selectedItemProperty().removeListener(listener);
            if(pck != null)
                pcks.add(pck);
            String text = filter.getText().trim().toLowerCase();
            newPcks=FXCollections.observableArrayList();
            for(int i=0; i<pcks.size(); i++) {
                if(pcks.get(i).protocol.getValue().toLowerCase().startsWith(text)) {
                    newPcks.add(pcks.get(i));
                }
            }
            packets.setItems(newPcks);
            packets.getSelectionModel().selectedItemProperty().addListener(listener);
        }
        catch(Exception e) {
            
        }
    }
    
}