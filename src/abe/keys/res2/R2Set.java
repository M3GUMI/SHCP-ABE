package abe.keys.res2;

import it.unisa.dia.gas.jpbc.Element;

public class R2Set {
    public String fingerprint;
    public Element D_i2;
    public Element C_i2;

    public R2Set(String fingerprint, Element d_i2, Element c_i2) {
        this.fingerprint = fingerprint;
        D_i2 = d_i2;
        C_i2 = c_i2;
    }
}
