package abe.keys;


import it.unisa.dia.gas.jpbc.Element;

public class MasterSecretKey {
    public Element gAlpha;
    public Element x;
    public Element y;

    public MasterSecretKey(Element gAlpha, Element x, Element y) {
        this.gAlpha = gAlpha;
        this.x = x;
        this.y = y;
    }
}
