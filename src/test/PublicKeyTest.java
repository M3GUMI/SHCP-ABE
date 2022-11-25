package test;

import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class PublicKeyTest {
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
    public static Element eGGAlpha;
    public static Element eGOmegaAlpha;
    public static Element gA;
    private static Map<String, Element> hMap1 = new HashMap<>();
    private static Map<String, Element> hMap2 = new HashMap<>();
    private static Map<String, Element> hMap_s1 = new HashMap<>();
    private static Map<String, Element> hMap_s2 = new HashMap<>();

    public static int filterCol = 47;
    private static MessageDigest messageDigest;
    public static int d = 150;
    public static int Z = 100;

    public static long setupTime(String url){
        long startTime = System.currentTimeMillis();

        Element g = G1.newRandomElement().getImmutable();
        Element g_sigma = G1.newRandomElement().getImmutable();
        Element omega = G1.newRandomElement().getImmutable();

        Element lambda = Zr.newRandomElement().getImmutable();
        Element mu = Zr.newRandomElement().getImmutable();
        Element x = Zr.newRandomElement().getImmutable();
        Element y = Zr.newRandomElement().getImmutable();
        Element a = Zr.newRandomElement().getImmutable();
        Element alpha = Zr.newRandomElement().getImmutable();

        Element gAlpha = g.powZn(alpha);

        setupTime(g, g_sigma, omega, lambda, mu, x, y, gAlpha, a, url);

        long endTime = System.currentTimeMillis();

        return endTime - startTime;
    }

    public static void setupTime(Element g1, Element g_sigma1, Element omega1, Element lambda1, Element mu1, Element x1, Element y1, Element gAlpha1, Element a1, String url){
        g = g1;
        g_sigma = g_sigma1;
        omega = omega1;
        lambda = lambda1;
        mu = mu1;
        g_sigmaX = g_sigma.powZn(x1);
        g_sigmaY = g_sigma.powZn(y1);
        eGGAlpha = bp.pairing(g,gAlpha1).getImmutable();
        eGOmegaAlpha = bp.pairing(gAlpha1,omega1).getImmutable();
        gA = g.powZn(a1);

        try {
            messageDigest = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        File file = new File(url);
        BufferedReader reader = null;
        String tempString = null;
        InputStreamReader isr = null;
        try {
            isr = new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        reader = new BufferedReader(isr);

        while (true) {
            try {
                if ((tempString = reader.readLine()) == null) break;
            } catch (IOException e) {
                e.printStackTrace();
            }

            Element h = G1.newRandomElement().getImmutable();
            Element h_ = G1.newRandomElement().getImmutable();

            hMap1.put(tempString, h);
            hMap2.put(H_f(tempString), h);
            hMap_s1.put(tempString, h_);
            hMap_s2.put(H_f(tempString), h_);
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

    public static Element getHByName(String attributeName){
        return hMap1.get(attributeName);
    }

    public static Element getHByFingerprint(String fingerprint){
        return hMap2.get(fingerprint);
    }

    public static Element getH_ByName(String attributeName){
        return hMap_s1.get(attributeName);
    }

    public static Element getH_ByFingerprint(String fingerprint){
        return hMap_s2.get(fingerprint);
    }
}
