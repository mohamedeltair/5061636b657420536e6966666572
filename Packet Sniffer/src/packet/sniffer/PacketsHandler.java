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
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
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
                Ip6 ip6 = Utilities.getIp6(packet);
                String source = "", destination = "";
                if(ip4!=null) {
                    source = FormatUtils.ip(ip4.source());
                    destination = FormatUtils.ip(ip4.destination());
                }
                else if(ip6!=null) {
                    source = FormatUtils.ip(ip6.source());
                    destination = FormatUtils.ip(ip6.destination());
                }
                else {
                    source = "no ip4, ip6";
                    destination = "no ip4, ip6";
                }
                d.addRow(new Packet((count++)+"", new Date(packet.getCaptureHeader().timestampInMillis()).toString(), source, destination,
                        Utilities.getStaticLastHeader(packet).getName(), packet.getCaptureHeader().wirelen()+"", ""));
                packets.add(packet);
            }  
        };  
        pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, "");   
        pcap.close();
    }
}