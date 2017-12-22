package packet.sniffer;

import com.jfoenix.controls.JFXButton;
import com.jfoenix.controls.JFXSnackbar;
import java.net.URL;
import java.util.*;
import java.util.ResourceBundle;
import javafx.application.Platform;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.event.Event;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.Region;
import javafx.scene.paint.Color;
import javafx.stage.Stage;
import javafx.stage.WindowEvent;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

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
    private AnchorPane root;
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
            JFXSnackbar snack=new JFXSnackbar(root);
            EventHandler handler =new EventHandler() {
                @Override
                public void handle(Event event) {
                      snack.close();
                }
            };
            snack.show("Please select an interface or click Refresh","Okay",3000,handler);
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
        emptyTable();
        fillTable();
    }
    @FXML
    void open(ActionEvent event) {
        FXMLLoader loader = new FXMLLoader();
           loader.setLocation(getClass().getResource("learning.fxml"));
         try {
             loader.load();       
        } catch(Exception e) {
           e.printStackTrace();
          }
                      Stage stage=(Stage)((Node)event.getSource()).getScene().getWindow();
         Parent root1 = loader.getRoot();             
            Scene scene1 = new Scene(root1);
           stage.setScene(scene1);
           stage.show();
        stage.setResizable(false);

    }
}
