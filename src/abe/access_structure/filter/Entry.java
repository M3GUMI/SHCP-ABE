package abe.access_structure.filter;


import abe.access_structure.node.PolicyAttribute;
import abe.keys.PublicKey;
import abe.util.SymmetricEncryptTool;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.ElementPowPreProcessing;
import it.unisa.dia.gas.jpbc.Field;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class Entry{
    private String fingerprint;
    private int row;
    private Element S_1;
    private Element S_2;

    public Entry(PolicyAttribute policyAttribute){
        Field Zr = PublicKey.Zr;

        fingerprint = policyAttribute.getFingerprint();
        row = policyAttribute.getX();

        Element ti = Zr.newElement(policyAttribute.getTi()).getImmutable();
        Element tj = Zr.newElement(policyAttribute.getTj()).getImmutable();
        Element Z = Zr.newElement(PublicKey.Z).getImmutable();
        Element lambda = PublicKey.lambda;
        Element mu = PublicKey.mu;
        ElementPowPreProcessing h_ = PublicKey.getH_ByFingerprint(fingerprint);
        ElementPowPreProcessing omega = PublicKey.omega;
        Element r_i = Zr.newRandomElement().getImmutable();

        S_1 = h_.powZn(r_i.mul(lambda.powZn(tj)).mul(mu.powZn(Z.sub(ti))).mul(-1)).getImmutable();
        S_2 = omega.powZn(r_i).getImmutable();
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public int getRow() {
        return row;
    }

    public Element getS_1() {
        return S_1;
    }

    public Element getS_2() {
        return S_2;
    }

    @Override
    public String toString() {
        return "Entry{" +
                "fingerprint='" + fingerprint + '\'' +
                ", row=" + row +
                ", S_1=" + S_1 +
                ", S_2=" + S_2 +
                '}';
    }
}
