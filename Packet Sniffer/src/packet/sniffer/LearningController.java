/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package packet.sniffer;

import com.jfoenix.controls.JFXButton;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Date;
import java.util.ResourceBundle;
import javafx.collections.FXCollections;
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
import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import static packet.sniffer.Main_Controller.stopBtnIsClicked;

/**
 * FXML Controller class
 *
 * @author ahmedsalah
 */
public class LearningController implements Initializable {  
    
    Learned learner; 
    @FXML
    private TableView<Recognized> result;

    @FXML
    private TableColumn<Recognized, String> num,recog, act, accCol;

    @Override
    public void initialize(URL url, ResourceBundle rb) {
        num.setCellValueFactory(cellData-> cellData.getValue().number);
        recog.setCellValueFactory(cellData-> cellData.getValue().recognised);
        act.setCellValueFactory(cellData-> cellData.getValue().actual);
        accCol.setCellValueFactory(cellData-> cellData.getValue().acc);
    }    
    public void filltable(ObservableList<Recognized> input){
        result.setItems(input);
    }
    
    public ArrayList<PcapPacket> Load(String fileName) {
        try{    
            ArrayList<PcapPacket> packets = new ArrayList();
    StringBuilder errbuf = new StringBuilder();  
    Pcap pcap = Pcap.openOffline(fileName,errbuf);
        //2-check if all OK
        if (pcap == null) {  
          System.err.printf("Error while opening device for capture: "  
    + errbuf.toString()); 
            System.out.println("null");
        }
        else {System.out.println("correctPCAP");}
        
        //3-create packet handler
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
               int count =1;
            @Override
            
            public void nextPacket(PcapPacket packet, String user) {
             
            
                packets.add(packet);
                
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
                
           
              
            }  
        };
        
        try {
           pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, "");
           return packets;
        }
        catch(Exception ex)
        {
            System.out.println("END OF FILE");
        }

        }
        catch (Exception e){}
          return new ArrayList();
    }
    
    @FXML
    void learn(ActionEvent event) throws IOException {
        try {
        FileChooser fc = new FileChooser();
       fc.setTitle("Select file to learn from");

        File selectedFile = fc.showOpenDialog(null);
        String fileName = selectedFile.getAbsolutePath();
        ArrayList<PcapPacket> packets = Load(fileName);
        learner = new Learned(packets);
        }
        catch(Exception e) {
            
        }
    }

    @FXML
    void recognise(ActionEvent event) {
        try {
        FileChooser fc = new FileChooser();
       fc.setTitle("Select file to be recognised");

        File selectedFile = fc.showOpenDialog(null);
        String fileName = selectedFile.getAbsolutePath();
        ArrayList<PcapPacket> packets = Load(fileName);
        ObservableList<Recognized> list=FXCollections.observableArrayList();
        for(int i=0; i<packets.size(); i++) {
            String actual =learner.getClassification(packets.get(i)),
                    rec =learner.identify(packets.get(i));
            Recognized recognized = new Recognized((i+1)+"", rec, actual,
                     actual.equals(rec)+"");
            list.add(recognized);
        }
        filltable(list);
        }
        catch(Exception e) {
            
        }
        
    }
    @FXML
    void back(ActionEvent event) {
        try{
            Parent root = FXMLLoader.load(getClass().getResource("mainwindow1.fxml"));
        Scene scene = new Scene(root);
        Stage stage=(Stage)result.getScene().getWindow();
        stage.setScene(scene);
        stage.setTitle("Devices List");
        stage.show();
        }
        catch(Exception e){
            System.out.println(e.toString());
        }
    }
}
