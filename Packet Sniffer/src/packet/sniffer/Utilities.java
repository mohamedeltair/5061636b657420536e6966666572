/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package packet.sniffer;

import java.util.ArrayList;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JHeaderPool;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.application.Html;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

/**
 *
 * @author elteir
 */
public class Utilities {
    public static int toUnsignedByte(byte val) {
        return (int)(val & 0x000000FF);
    }
    public static Html getHtml(PcapPacket packet) {
        return packet.getHeader(new Html());   
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
    public static ArrayList<JHeader> getHeaders(JPacket packet) {  
    return getHeaders(packet, false);   
    }  
    public static ArrayList<JHeader> getHeaders(JPacket packet, boolean payloadOk) {  
        ArrayList<JHeader> headers = new ArrayList();
        int last = packet.getHeaderCount() - 1;  

        if (!payloadOk && packet.getHeaderIdByIndex(last) == Payload.ID  
            && last > 0) {  
            last--; // We want the last header before payload  
        }  
        for(int i=0; i<=last; i++) {
            final JHeader header =  
                JHeaderPool.getDefault().getHeader(packet.getHeaderIdByIndex(i));  
            packet.getHeaderByIndex(i, header);  
            headers.add(header);
        }

        return headers;  
    }  
    
}