package abe.keys.res1;

import it.unisa.dia.gas.jpbc.Element;

public class R1Set {
    public Element D_i1;
    public Element C_i1;
    public byte[] c_i;
    public String fingerprint;

    public R1Set(Element d_i1, Element c_i1, byte[] c_i, String fingerprint) {
        D_i1 = d_i1;
        C_i1 = c_i1;
        this.c_i = c_i;
        this.fingerprint = fingerprint;
    }
}
