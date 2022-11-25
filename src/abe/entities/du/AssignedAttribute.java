package abe.entities.du;

import abe.keys.PublicKey;

import java.util.Random;

public class AssignedAttribute {
    private String attributeName;
    private int ta;
    private int tb;

    public AssignedAttribute(String assignedAttribute){
        if (assignedAttribute.matches("[a-z,A-Z,0-9]*:[0-9]*-[0-9]*")) {
            int index1 = assignedAttribute.indexOf(":");
            int index2 = assignedAttribute.indexOf("-");
            attributeName = assignedAttribute.substring(0, index1);
            String attributeLowerLimit = assignedAttribute.substring(index1 + 1, index2);
            String attributeUpperLimit = assignedAttribute.substring(index2 + 1);

            ta = Integer.parseInt(attributeLowerLimit);
            tb = Integer.parseInt(attributeUpperLimit);

        } else if (assignedAttribute.matches("[a-z,A-Z,0-9]*")) {
            this.attributeName = assignedAttribute;
            ta = 0;
            tb = PublicKey.Z;
        }
    }

    public String getAttributeName() {
        return attributeName;
    }

    public int getTa() {
        return ta;
    }

    public int getTb() {
        return tb;
    }
}
