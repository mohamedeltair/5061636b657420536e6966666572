/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package packet.sniffer;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;

/**
 *
 * @author elteir
 */
public class PacketsHandler extends Thread {
    private int index;
    List<PcapIf> alldevs;  
    StringBuilder errbuf; 
    public static Pcap pcap;
    
    Main_Controller d;
    int count=1;
    static ArrayList<PcapPacket> packets = new ArrayList();
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
         pcap =  
            Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);  
  
        if (pcap == null) {  
            System.err.printf("Error while opening device for capture: "  
                + errbuf.toString());  
            return;  
        }  
           
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {  
  
            
             
            public void nextPacket(PcapPacket packet, String user) {  
                try {
                
                    System.out.printf("Received packet at %s caplen=%-4d len=%-4d %s\n",  
                        new Date(packet.getCaptureHeader().timestampInMillis()),   
                        packet.getCaptureHeader().caplen(),  
                        packet.getCaptureHeader().wirelen(),  
                        user                                  
                        );
                    Ip4 ip4 = Utilities.getIp4(packet);

                    Ip6 ip6 = Utilities.getIp6(packet);
                    Ethernet ethernet = Utilities.getEthernet(packet);
                    String source = "", destination = "";
                    if(ip4!=null) {
                        source = FormatUtils.ip(ip4.source());
                        destination = FormatUtils.ip(ip4.destination());
                    }
                    else if(ip6!=null) {
                        //source = ip6.source().toString();
                        //destination = ip6.destination().toString();
                        //source = FormatUtils.asStringIp6(ip6.source(), false);
                        //destination = FormatUtils.asStringIp6(ip6.destination(), false);
                        //destination = ip6.source().length+"";
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
                    d.addRow(new Packet((count++)+"", new Date(packet.getCaptureHeader().timestampInMillis()).toString(), source, destination,
                            headers.get(last).getName(), packet.getCaptureHeader().wirelen()+"", "Protocols involved: "+all));
                    packets.add(packet);
                }
                catch(Exception e) {
                    
                }
            }  
        };  
        pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, "");   
       
    }
}