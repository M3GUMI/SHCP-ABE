package abe.entities.aa;


import abe.entities.du.AssignedAttribute;
import abe.entities.du.AttributeSecretKey;
import abe.keys.ElementTest;
import abe.keys.MasterSecretKey;
import abe.keys.PublicKey;
import abe.keys.Signature;
import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.List;

public class AttributeAuthority {
    private static Field G1 = PublicKey.G1;
    private static Field Zr = PublicKey.Zr;
    private static Field GT = PublicKey.GT;
    private static Pairing bp = PublicKey.bp;
    private static MasterSecretKey msk;

    public static void setup(){
        Element omega = G1.newRandomElement().getImmutable();
        ElementPowPreProcessing omega_pre = omega.getElementPowPreProcessing();
        PairingParameters type1Params = PairingFactory.getPairingParameters("src/resources/a.properties");

        Element G_p_1 = ElementUtils.getGenerator(bp, omega, type1Params, 0, 2).getImmutable();
        Element g = G_p_1.powZn(Zr.newRandomElement());

        Element g_sigma = G_p_1.powZn(Zr.newRandomElement());

        Element lambda = Zr.newRandomElement().getImmutable();
        Element mu = Zr.newRandomElement().getImmutable();
        Element x = Zr.newRandomElement().getImmutable();
        Element y = Zr.newRandomElement().getImmutable();
        Element a = Zr.newRandomElement().getImmutable();
        Element alpha = Zr.newRandomElement().getImmutable();

        Element gAlpha = g.powZn(alpha);

        PublicKey.setup(g, g_sigma, omega, lambda, mu, x, y, gAlpha, a);

        msk = new MasterSecretKey(gAlpha, x, y);
    }

    public static AttributeSecretKey keyGen(List<AssignedAttribute> assignedAttributes){
        return new AttributeSecretKey(assignedAttributes, msk);
    }

    public static long keyGenTime(List<AssignedAttribute> assignedAttributes){
        long startTime = System.currentTimeMillis();
        new AttributeSecretKey(assignedAttributes, msk);
        long endTime = System.currentTimeMillis();

        return endTime - startTime;
    }
}
