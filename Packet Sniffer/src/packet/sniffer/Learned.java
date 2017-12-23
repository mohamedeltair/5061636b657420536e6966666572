/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package packet.sniffer;

import java.io.IOException;
import javafx.beans.property.SimpleStringProperty;

import java.util.*;
import javafx.beans.property.SimpleStringProperty;
import javafx.util.*;
import org.jnetpcap.packet.*;

class Node {
    int attrNum;
    ArrayList<Pair<Integer, Node>> children;
    String protocols;

    public Node(int attrNum, ArrayList<Pair<Integer, Node>> children, String protocols) {
        this.attrNum = attrNum;
        this.children = children;
        this.protocols = protocols;
    }
    
}

public class Learned {
    SimpleStringProperty number,recognised,actual,acc;
    ArrayList<PcapPacket> packets = new ArrayList();
    Node head;
    int[][][] possibleVals = {{{8,0}, {8,6}, {134, 221}, {-1}},{{6},{1},{17},{-1}}};
    int[][] wherePossible = {{12,13},{23}};
    
    public ArrayList<Integer> allAttrs() {
        ArrayList<Integer> attrs = new ArrayList();
        for(int i=0; i<possibleVals.length; i++) {
            attrs.add(i);
        }
        return attrs;
    }
    
    public Learned(ArrayList<PcapPacket> packets) throws IOException {
        this.packets = packets;
        head = decisionTree(packets, allAttrs(), new ArrayList());
        System.out.println("learned!");
    }
    
    public String getClassification(PcapPacket packet) {
        String all="";
        ArrayList<JHeader> headers = Utilities.getHeaders(packet);
        int last = headers.get(headers.size()-1).getName().equals("Html")?headers.size()-2:headers.size()-1;
        for(int i=0; i<=last; i++) {
            all+=headers.get(i).getName();
            if(i!=last)
                all+=", ";
        }
        return all;
    }
    
    public HashMap<String, Integer>getHash(ArrayList<PcapPacket> packets) {
        HashMap<String,Integer>hash = new HashMap();
        for(int ii=0; ii<packets.size(); ii++) {
            PcapPacket packet = packets.get(ii);
            String all = getClassification(packet);
            Object oc =hash.get(all); 
            if(oc==null) {
                hash.put(all, 1);
            }
            else {
                hash.put(all, (Integer)oc+1);
            }
        }
        return hash;
    }
    
    public String plurality(ArrayList<PcapPacket> packets) {
        HashMap<String, Integer>hash = getHash(packets);
        String ret="";
        int max=0;
        Iterator it = hash.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry pair = (Map.Entry)it.next();
            if((Integer)pair.getValue()>max) {
                ret = (String)pair.getKey();
            }
            it.remove();
        }
        return ret;
    } 
    
    public boolean sameClassification(ArrayList<PcapPacket> packets) {
        String same=getClassification(packets.get(0));
        for(int i=1; i<packets.size(); i++) {
            if(!getClassification(packets.get(i)).equals(same)) {
                return false;
            }
        }
        return true;
    }
    
    boolean conforms(int attr, int what, byte[] data) {
        if(what==possibleVals[attr].length-1) {
        //System.out.println("hob");
            for(int i=0; i<possibleVals[attr].length - 1 ; i++) {
                if(conforms(attr, i, data)) {
                    return false;
                }
            }
            return true;
        }
        for(int i=0; i<possibleVals[attr][what].length; i++) {
            System.out.println(attr+", "+what+", "+i);
            if(data[wherePossible[attr][i]] != possibleVals[attr][what][i]) {
                return false;
            }
        }
        return true;
    }
    
    public ArrayList<PcapPacket> getAttrPackets(ArrayList<PcapPacket> packets, int attr, int what) {
        ArrayList<PcapPacket> attrPackets = new ArrayList();
        for(int i=0; i<packets.size(); i++) {
            PcapPacket packet = packets.get(i);
            byte[] data = packet.getByteArray(0, packet.size());
            if(conforms(attr, what, data)) {
                attrPackets.add(packet);
            }
        }
        return attrPackets;
    }
    
    public double infoGain(ArrayList<PcapPacket> packets, int attr) {
        double sum = 0;
        for(int i=0; i<possibleVals[attr].length; i++) {
            double localSum=0;
            ArrayList<PcapPacket> attrPackets = getAttrPackets(packets, attr, i);
            HashMap<String, Integer> hash = getHash(attrPackets);
            int tot= attrPackets.size();
            Iterator it = hash.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry pair = (Map.Entry)it.next();
                int val =(Integer)pair.getValue();
                if(val!=0) {
                    double ratio=val/(double)tot; 
                    localSum += -ratio*(Math.log(ratio)/Math.log(2));
                }
                it.remove();
            }
            double bigRatio = (attrPackets.size()/(double)packets.size());
            sum += bigRatio*localSum;
        }
        return 1-sum;
    }
    
    public Node decisionTree(ArrayList<PcapPacket> packets, ArrayList<Integer> attrs, ArrayList<PcapPacket> parentPackets) throws IOException {
        //System.out.println(attrs.size());
       // System.in.read();
        if(packets.isEmpty()) {
               // System.out.println("ex empty");
                //System.in.read();
            return new Node(-1, null, plurality(parentPackets));
        }
        else if(sameClassification(packets)) {
                //System.out.println("same class");
                //System.in.read();
            return new Node(-1, null, getClassification(packets.get(0)));
        }
        else if(attrs.isEmpty()) {
               // System.out.println("attr empty");
               // System.in.read();
            return new Node(-1, null, plurality(packets));
        }
        else {
            Node me = new Node(-1,new ArrayList(), "");
            double max=-1;
            int chosenAttr=-1;
            for(int i=0; i<attrs.size(); i++) {
                double gainI = infoGain(packets, attrs.get(i));
                if(gainI>max) {
                    max = gainI;
                    chosenAttr = attrs.get(i);
                }
            }
            me.attrNum = chosenAttr;
            ArrayList<Integer> newAttrs = new ArrayList();
            for(int i=0; i<attrs.size(); i++) {
                if(attrs.get(i) != chosenAttr) {
                    newAttrs.add(attrs.get(i));
                }
            }
            for(int i=0; i<possibleVals[chosenAttr].length; i++) {
                ArrayList<PcapPacket> attrPackets = getAttrPackets(packets, chosenAttr, i);
                Node newChild = decisionTree(attrPackets, newAttrs, packets);
                me.children.add(new Pair<>(i, newChild));
            }
            return me;
        }
    }
    
    String identify(byte[] data, Node node) {
        if(!node.protocols.equals("")) {
            return node.protocols;
        }
        int attr = node.attrNum;
        for(int i=0; i<node.children.size(); i++) {
            int what = node.children.get(i).getKey();
            if(conforms(attr, what, data)) {
                return identify(data, node.children.get(i).getValue());
            }
        }
        return "";
    }
    
    String identify(PcapPacket packet) {
        return identify(packet.getByteArray(0, packet.size()), head);
    }
    
}
