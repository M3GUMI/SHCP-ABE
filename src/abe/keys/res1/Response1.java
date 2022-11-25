package abe.keys.res1;

import it.unisa.dia.gas.jpbc.Element;

import java.util.List;

public class Response1 {
    public Element C1;
    public Element C_1;
    public List<R1Set> sets;

    public Response1(Element c1, Element c_1, List<R1Set> sets) {
        C1 = c1;
        C_1 = c_1;
        this.sets = sets;
    }
}
