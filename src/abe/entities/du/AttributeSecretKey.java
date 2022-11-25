package abe.entities.du;

import abe.keys.ElementTest;
import abe.keys.MasterSecretKey;
import abe.keys.PublicKey;
import abe.keys.Signature;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.ElementPowPreProcessing;
import it.unisa.dia.gas.jpbc.Field;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AttributeSecretKey {
    public Element K;
    public Element L_1;
    public Element L_2;
    public Element L_3;
    public Signature signature;
    public Map<String, UserAttribute> userMap1;
    public Map<String, UserAttribute> userMap2;

    public AttributeSecretKey(List<AssignedAttribute> assignedAttributes, MasterSecretKey msk){
        Field Zr = PublicKey.Zr;
        Element t = Zr.newRandomElement().getImmutable();
        Element t_ = Zr.newRandomElement().getImmutable();
        Element t__ = Zr.newRandomElement().getImmutable();
        ElementPowPreProcessing g = PublicKey.g;
        Element gA = PublicKey.gA;
        ElementPowPreProcessing omega = PublicKey.omega;
        Element lambda = PublicKey.lambda;
        Element mu = PublicKey.mu;
        ElementPowPreProcessing g_sigma = PublicKey.g_sigma;
        Element gAlpha = msk.gAlpha;
        Element x = msk.x;
        Element y = msk.y;

        K = gAlpha.mul(gA.powZn(t));
        L_1 = g.powZn(t).getImmutable();
        L_2 = omega.powZn(t).getImmutable();
        L_3 = omega.powZn(t_).getImmutable();

        Element element = (x.add(PublicKey.H_sigma(L_3)).add(y.mul(t__))).invert();
        Element sigma = g_sigma.powZn(element).getImmutable();
        signature = new Signature(sigma, t__);

        userMap1 = new HashMap<String, UserAttribute>();
        userMap2 = new HashMap<String, UserAttribute>();

        for (AssignedAttribute assignedAttribute : assignedAttributes) {
            String attributeName = assignedAttribute.getAttributeName();
            String fingerprint = PublicKey.H_f(attributeName);

            Element ta = Zr.newElement(assignedAttribute.getTa()).getImmutable();
            Element tb = Zr.newElement(assignedAttribute.getTb()).getImmutable();
            Element Z = Zr.newElement(PublicKey.Z).getImmutable();

            ElementPowPreProcessing h = PublicKey.getHByName(attributeName);
            ElementPowPreProcessing h_ = PublicKey.getH_ByName(attributeName);
            Element K_x1 = h.powZn(t).getImmutable();
            Element K_x2 = h_.powZn(t.mul(lambda.powZn(ta)).mul(mu.powZn(Z.sub(tb)))).getImmutable();
            Element K_x3 = h_.powZn(t_.mul(lambda.powZn(ta)).mul(mu.powZn(Z.sub(tb)))).getImmutable();

            UserAttribute userAttribute = new UserAttribute(attributeName, K_x1, K_x2, K_x3, assignedAttribute.getTa(), assignedAttribute.getTb());

            userMap1.put(attributeName, userAttribute);
            userMap2.put(fingerprint, userAttribute);
        }
    }

    public UserAttribute getAttributeByName(String name){
        return userMap1.get(name);
    }

    public UserAttribute getAttributeByFingerprint(String fingerprint){
        return userMap2.get(fingerprint);
    }
}
