package abe.keys.res2;

import it.unisa.dia.gas.jpbc.Element;

import java.util.List;

public class Response2 {
    public byte[] C_SE;
    public Element C2;
    public Element C_2;
    public List<R2Set> sets;

    public Response2(byte[] c_SE, Element c2, Element c_2, List<R2Set> sets) {
        C_SE = c_SE;
        C2 = c2;
        C_2 = c_2;
        this.sets = sets;
    }
}
