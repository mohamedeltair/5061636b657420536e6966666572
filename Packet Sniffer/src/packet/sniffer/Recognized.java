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
public class Recognized {
    SimpleStringProperty number, recognised, actual, acc;
    public Recognized(String number, String recognised, String actual, String acc) {
	this.number = new SimpleStringProperty(number);
        this.recognised = new SimpleStringProperty(recognised);
        this.actual = new SimpleStringProperty(actual);
        this.acc = new SimpleStringProperty(acc);
    }
}
