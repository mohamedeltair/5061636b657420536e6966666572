/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package packet.sniffer;

import javafx.beans.property.SimpleStringProperty;

import java.util.*;
import javafx.beans.property.SimpleStringProperty;
import javafx.util.*;

class Node {
    int attrNum;
    ArrayList<Pair<Integer, Node>> children;
}

public class Learned {
    SimpleStringProperty number,recognised,actual,acc;

    public Learned(String number, String recognised, String actual, String acc) {
        this.number = new SimpleStringProperty(number);
        this.recognised = new SimpleStringProperty(recognised);
        this.actual = new SimpleStringProperty(actual);
        this.acc = new SimpleStringProperty(acc);
    }
    
}
