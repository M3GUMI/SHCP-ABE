package abe.keys;

import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class PublicKey {
    public static Pairing bp = PairingFactory.getPairing("src/resources/a.properties");
    public static Field G1 = bp.getG1();
    public static Field Zr = bp.getZr();
    public static Field GT = bp.getGT();
    public static ElementPowPreProcessing g;
    public static ElementPowPreProcessing g_sigma;
    public static ElementPowPreProcessing omega;
    public static Element lambda;
    public static Element mu;
    public static Element g_sigmaX;
    public static Element g_sigmaY;
    public static Element eGGAlpha;
    public static Element eGOmegaAlpha;
    public static Element gA;
    private static Map<String, ElementPowPreProcessing> hMap1 = new HashMap<>();
    private static Map<String, ElementPowPreProcessing> hMap2 = new HashMap<>();
    private static Map<String, ElementPowPreProcessing> hMap_s1 = new HashMap<>();
    private static Map<String, ElementPowPreProcessing> hMap_s2 = new HashMap<>();

    public static int filterCol = 47;
    private static MessageDigest messageDigest;
    public static int d = 150;
    public static int Z = 100;

    public static void setup(Element g1, Element g_sigma1, Element omega1, Element lambda1, Element mu1, Element x1, Element y1, Element gAlpha1, Element a1){
        g = g1.getElementPowPreProcessing();
        g_sigma = g_sigma1.getElementPowPreProcessing();
        omega = omega1.getElementPowPreProcessing();
        lambda = lambda1;
        mu = mu1;
        g_sigmaX = g_sigma.powZn(x1).getImmutable();
        g_sigmaY = g_sigma.powZn(y1).getImmutable();
        eGGAlpha = bp.pairing(g1,gAlpha1).getImmutable();
        eGOmegaAlpha = bp.pairing(gAlpha1,omega1).getImmutable();
        gA = g.powZn(a1).getImmutable();

        try {
            messageDigest = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        File file = new File("src/resources/attributesets.txt");
        BufferedReader reader = null;
        String tempString = null;
        InputStreamReader isr = null;
        try {
            isr = new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        reader = new BufferedReader(isr);

        PairingParameters type1Params = PairingFactory.getPairingParameters("src/resources/a.properties");
        Element G_p_1 = ElementUtils.getGenerator(bp, omega1, type1Params, 0, 2).getImmutable();
        Element G_p_2 = ElementUtils.getGenerator(bp, omega1, type1Params, 1, 2).getImmutable();

        while (true) {
            try {
                if ((tempString = reader.readLine()) == null) break;
            } catch (IOException e) {
                e.printStackTrace();
            }

            Element h = G_p_1.powZn(Zr.newRandomElement());
            ElementPowPreProcessing h_pre = h.getElementPowPreProcessing();
            Element h_ = G_p_2.powZn(Zr.newRandomElement());
            ElementPowPreProcessing h__pre = h_.getElementPowPreProcessing();

            hMap1.put(tempString, h_pre);
            hMap2.put(H_f(tempString), h_pre);
            hMap_s1.put(tempString, h__pre);
            hMap_s2.put(H_f(tempString), h__pre);
        }
        try {
            isr.close();
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static String H_f(String attributeName){
        return new String(messageDigest.digest(attributeName.getBytes(StandardCharsets.UTF_8)));
    }

    public static Element H_sigma(Element element){
        byte[] byteElement = element.toBytes();
        return Zr.newElementFromHash(byteElement, 0, byteElement.length);
    }

    public static ElementPowPreProcessing getHByName(String attributeName){
        return hMap1.get(attributeName);
    }

    public static ElementPowPreProcessing getHByFingerprint(String fingerprint){
        return hMap2.get(fingerprint);
    }

    public static ElementPowPreProcessing getH_ByName(String attributeName){
        return hMap_s1.get(attributeName);
    }

    public static ElementPowPreProcessing getH_ByFingerprint(String fingerprint){
        return hMap_s2.get(fingerprint);
    }
}
