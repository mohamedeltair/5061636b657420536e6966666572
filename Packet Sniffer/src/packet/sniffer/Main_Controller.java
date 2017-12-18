package packet.sniffer;

import com.jfoenix.controls.JFXTextArea;
import com.jfoenix.controls.JFXTextField;
import java.io.File;
import java.net.URL;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.ResourceBundle;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.collections.transformation.SortedList;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.stage.Stage;
import org.jnetpcap.JBufferHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
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
    private JFXTextField filter;
    
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
    
    public void Stop()
    {
        PacketsHandler.pcap.breakloop();  
    }
    
      public void Save()
    {
        StringBuilder errbuf = new StringBuilder();  
String fname = "tests/test-afs.pcap";  
  
Pcap pcap = Pcap.openOffline(fname, errbuf);
    String ofile = "tmp-capture-file.cap";
    
    
   PcapDumper dumper = PacketsHandler.pcap.dumpOpen(ofile); // output file  
  
   JBufferHandler<PcapDumper> dumpHandler = new JBufferHandler<PcapDumper>() {  
  
  public void nextPacket(PcapHeader header, JBuffer buffer, PcapDumper dumper) {  
  
    dumper.dump(header, buffer);  
  }      
   };
   PacketsHandler.pcap.loop(10,dumpHandler, dumper);
  
      File file = new File(ofile);  

dumper.close(); // Won't be able to delete without explicit close  
    PacketsHandler.pcap.close();
    }
      
     public void Load()
    {
        String fname = "tmp-capture-file.cap";  
  StringBuilder errbuf = new StringBuilder(); 
        Pcap pcap = Pcap.openOffline(fname, errbuf);  
        if (pcap == null) {  
    System.err.printf("Error while opening device for capture: "  
    + errbuf.toString());  
    }
    }
     
 
    public String check(Object o){
        if(o == null) return "Protocol doesn't exist";
        return o.toString();
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
        });
        filter.textProperty().addListener((observable, oldValue, newValue) -> {
            FilteredList<Packet> filteredData = new FilteredList<>(pcks, p -> true);
            filteredData.setPredicate(packet -> {
                if (newValue == null || newValue.isEmpty()) {
                    return true;
                }

                String lowerCaseFilter = newValue.toLowerCase();

                if (packet.getProtocol().getValue().toLowerCase().contains(lowerCaseFilter)) {
                    return true; 
                } 
                return false; 
            });
            SortedList<Packet> sortedData = new SortedList<>(filteredData);
        sortedData.comparatorProperty().bind(packets.comparatorProperty());
        packets.setItems(sortedData);
        });
    }
    public void addRow(Packet pck){
        pcks.add(pck);
        packets.setItems(pcks);
    }
    
}