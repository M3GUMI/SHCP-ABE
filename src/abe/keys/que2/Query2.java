package abe.keys.que2;

import abe.keys.Signature;
import it.unisa.dia.gas.jpbc.Element;

import java.util.List;

public class Query2 {
    public Signature signature;
    public Element L_3;
    public List<Q2Set> sets;

    public Query2(Signature signature, Element l_3, List<Q2Set> sets) {
        this.signature = signature;
        L_3 = l_3;
        this.sets = sets;
    }
}
