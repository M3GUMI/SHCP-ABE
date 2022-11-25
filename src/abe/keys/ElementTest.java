package abe.keys;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class ElementTest {
    public static Pairing bp = PairingFactory.getPairing("src/resources/a.properties");
    public static Field G1 = bp.getG1();
    public static Field Zr = bp.getZr();
    public static Field GT = bp.getGT();
    public static Element g;
    public static Element g_sigma;
    public static Element omega;
    public static Element lambda;
    public static Element mu;
    public static Element g_sigmaX;
    public static Element g_sigmaY;
    public static Element gAlpha;
    public static Element eGGAlpha;
    public static Element a;
    public static Element t;
    public static Element s_;
    public static Element P_P;

    public static void setup(Element g1, Element g_sigma1, Element omega1, Element lambda1, Element mu1, Element x1, Element y1, Element gAlpha1, Element a1){
        g = g1;
        g_sigma = g_sigma1;
        omega = omega1;
        lambda = lambda1;
        mu = mu1;
        g_sigmaX = g_sigma.powZn(x1);
        g_sigmaY = g_sigma.powZn(y1);
        eGGAlpha = bp.pairing(g, gAlpha1).getImmutable();
        gAlpha = gAlpha1;
        a = a1;
    }

    public static void setT(Element t1){
        t = t1;
    }

    public static void setS_(Element s_1, Element P_P1){
        s_ = s_1;
        P_P = P_P1;
    }
}
