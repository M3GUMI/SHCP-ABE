package abe.access_structure.node;


import abe.keys.PublicKey;

import java.util.Random;

public class PolicyAttribute extends TreeNode {
    private String attributeName;
    private String fingerprint;
    private int ti;
    private int tj;
    //x是对象在A中的下标
    private int x;

    public PolicyAttribute(String attribute) {
        if (attribute.matches("[a-z,A-Z,0-9]*:[0-9]*-[0-9]*")) {
            int index1 = attribute.indexOf(":");
            int index2 = attribute.indexOf("-");
            attributeName = attribute.substring(0, index1);
            fingerprint = PublicKey.H_f(attributeName);
            String attributeLowerLimit = attribute.substring(index1 + 1, index2);
            String attributeUpperLimit = attribute.substring(index2 + 1);

            this.ti = Integer.parseInt(attributeLowerLimit);
            this.tj = Integer.parseInt(attributeUpperLimit);

        } else if (attribute.matches("[a-z,A-Z,0-9]*")) {
            this.attributeName = attribute;
            fingerprint = PublicKey.H_f(attributeName);
            Random random = new Random();
            int num1 = random.nextInt(PublicKey.Z);
            int num2 = random.nextInt(PublicKey.Z);
            if (num1 > num2) {
                tj = num1;
                ti = num2;
            } else {
                ti = num1;
                tj = num2;
            }
        }
    }

    public String getAttributeName() {
        return attributeName;
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public int getTi() {
        return ti;
    }

    public int getTj() {
        return tj;
    }

    @Override
    public String getName() {
        return attributeName;
    }

    public int getX() {
        return x;
    }

    public void setX(int x) {
        this.x = x;
    }

    @Override
    public String toString() {
        return attributeName+":"+ti+"-"+tj;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((attributeName == null) ? 0 : attributeName.hashCode());
        result = prime * result + x;
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (!super.equals(obj))
            return false;
        if (!(obj instanceof PolicyAttribute))
            return false;
        PolicyAttribute other = (PolicyAttribute) obj;
        if (attributeName == null) {
            if (other.attributeName != null)
                return false;
        } else if (!attributeName.equals(other.attributeName))
            return false;
        return x == other.x;
    }
}
