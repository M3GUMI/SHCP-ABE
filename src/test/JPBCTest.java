package test;

import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1CurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1TateNafProjectiveMillerPairingMap;
import it.unisa.dia.gas.plaf.jpbc.pairing.map.DefaultPairingPreProcessing;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;
import org.junit.Test;

import java.math.BigInteger;

public class JPBCTest {
    Pairing bp = PairingFactory.getPairing("src/resources/a.properties");
    Field G1 = bp.getG1();
    Field Zr = bp.getZr();
    Field GT = bp.getGT();

    @Test
    public void mulTest(){

        Element g = G1.newRandomElement().getImmutable();
        Element x = Zr.newRandomElement();
        Element gX = g.powZn(x);
        Element eGG = bp.pairing(g,g).getImmutable();
        System.out.println(gX.isImmutable());
        System.out.println(eGG.isImmutable());
    }

    @Test
    public void genTest(){
        TypeA1CurveGenerator pg = new TypeA1CurveGenerator(3, 256);
        PairingParameters typeA1Params = pg.generate();
        Pairing pairing = PairingFactory.getPairing(typeA1Params);

        System.out.println(typeA1Params);
    }

    @Test
    public void getBigInteger(){
        BigInteger i1 = new BigInteger("76491928460535270672624562540842404795129722138725321016913491374451096721639");
        BigInteger i2 = new BigInteger("102794501177378470342496238013968311187281438070229594984442199853861531556371");

        System.out.println(i1.multiply(i2));
    }

    @Test
    public void toBytesTest(){
        Element in1 = G1.newRandomElement().getImmutable();
        Element z = Zr.newRandomElement().getImmutable();
        ElementPowPreProcessing ppp = in1.getElementPowPreProcessing();
        Element generator = G1.newRandomElement().getImmutable();
        PairingParameters type1Params = PairingFactory.getPairingParameters("src/resources/a.properties");

        long startTime = System.currentTimeMillis();
        G1.newRandomElement();
        long endTime = System.currentTimeMillis();
        System.out.println(endTime-startTime);

        startTime = System.currentTimeMillis();
        Element z1 = Zr.newRandomElement().getImmutable();
        endTime = System.currentTimeMillis();
        System.out.println(endTime-startTime);

        startTime = System.currentTimeMillis();
        endTime = System.currentTimeMillis();
        System.out.println(endTime-startTime);

        startTime = System.currentTimeMillis();
        Element G_p_1 = ElementUtils.getGenerator(bp, generator, type1Params, 0, 2).getImmutable();
        endTime = System.currentTimeMillis();
        System.out.println(endTime-startTime);

        startTime = System.currentTimeMillis();
        Element G_p_2 = ElementUtils.getGenerator(bp, generator, type1Params, 1, 2).getImmutable();
        System.out.println(G_p_2);
        endTime = System.currentTimeMillis();
        System.out.println(endTime-startTime);

        startTime = System.currentTimeMillis();
        Element G_p_3 = ElementUtils.getGenerator(bp, generator, type1Params, 1, 2).getImmutable();
        System.out.println(G_p_3);
        endTime = System.currentTimeMillis();
        System.out.println(endTime-startTime);

        System.out.println(bp.pairing(G_p_1,G_p_2));
        System.out.println(bp.pairing(G_p_1,G_p_3));
        System.out.println(bp.pairing(G_p_2,G_p_3));

        startTime = System.currentTimeMillis();
        Element out2 = in1.powZn(z);
        endTime = System.currentTimeMillis();
        System.out.println(endTime-startTime);
    }

    @Test
    public void preProcessedTest(){
        Element in1 = G1.newRandomElement();

        long startTime = System.currentTimeMillis();
        PairingPreProcessing ppp = bp.getPairingPreProcessingFromElement(in1);
        long endTime = System.currentTimeMillis();
        System.out.println(endTime-startTime);

        startTime = System.currentTimeMillis();
        ElementPowPreProcessing preProcessing = in1.getElementPowPreProcessing();
        endTime = System.currentTimeMillis();
        System.out.println(endTime-startTime);

        startTime = System.currentTimeMillis();
        ppp.pairing(in1);
        endTime = System.currentTimeMillis();
        System.out.println(endTime-startTime);

        startTime = System.currentTimeMillis();
        bp.pairing(in1, in1);
        endTime = System.currentTimeMillis();
        System.out.println(endTime-startTime);
    }

    @Test
    public void byteLengthTest(){
        Element g = G1.newRandomElement();
        System.out.println(g.toBytes().length);
    }

    @Test
    public void toSubGroupTest(){
        Element generator = G1.newRandomElement().getImmutable();
        PairingParameters type1Params = PairingFactory.getPairingParameters("src/resources/a.properties");
//        Field G_p_1 = ElementUtils.getGenerator(bp, generator, type1Params, 0, 2).getImmutable().getField();
//        Field G_p_2 = ElementUtils.getGenerator(bp, generator, type1Params, 1, 2).getImmutable().getField();
//
//        Element g1 = G_p_1.newRandomElement().getImmutable();
//        Element g2 = G_p_2.newRandomElement().getImmutable();

        Element g1 = ElementUtils.getGenerator(bp, generator, type1Params, 0, 2).getImmutable();
        Element g2 = ElementUtils.getGenerator(bp, generator, type1Params, 1, 2).getImmutable();
        System.out.println(bp.pairing(g1,g2));
    }
}
