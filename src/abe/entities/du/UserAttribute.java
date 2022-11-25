package abe.entities.du;

import abe.keys.PublicKey;
import it.unisa.dia.gas.jpbc.Element;

public class UserAttribute {
    private String attributeName;
    private String fingerprint;
    private Element Kx1;
    private Element Kx2;
    private Element Kx3;
    private int ta;
    private int tb;

    public UserAttribute(String attributeName, Element kx1, Element kx2, Element kx3, int ta, int tb) {
        this.attributeName = attributeName;
        this.fingerprint = PublicKey.H_f(attributeName);
        Kx1 = kx1;
        Kx2 = kx2;
        Kx3 = kx3;
        this.ta = ta;
        this.tb = tb;
    }

    public String getAttributeName() {
        return attributeName;
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public Element getKx1() {
        return Kx1;
    }

    public Element getKx2() {
        return Kx2;
    }

    public Element getKx3() {
        return Kx3;
    }

    public int getTa() {
        return ta;
    }

    public int getTb() {
        return tb;
    }
}
