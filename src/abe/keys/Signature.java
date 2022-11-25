package abe.keys;

import it.unisa.dia.gas.jpbc.Element;

public class Signature {
    private Element sigma;
    private Element t__;

    public Signature(Element sigma, Element t__) {
        this.sigma = sigma;
        this.t__ = t__;
    }

    public Element getSigma() {
        return sigma;
    }

    public Element getT__() {
        return t__;
    }
}
