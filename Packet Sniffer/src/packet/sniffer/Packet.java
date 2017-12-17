/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package packet.sniffer;

import javafx.beans.property.SimpleStringProperty;

/**
 *
 * @author elteir
 */
public class Packet {
    SimpleStringProperty no,time,source,dest,protocol,length,info;

    public Packet(String no, String time, String source, String dest, String protocol, String length, String info) {
        this.no = new SimpleStringProperty(no);
        this.time = new SimpleStringProperty(time);
        this.source = new SimpleStringProperty(source);
        this.dest = new SimpleStringProperty(dest);
        this.protocol = new SimpleStringProperty(protocol);
        this.length = new SimpleStringProperty(length);
        this.info = new SimpleStringProperty(info);
    }

    public SimpleStringProperty getProtocol() {
        return protocol;
    }
    
}
