package abe.entities.tsp;

import abe.access_structure.filter.CuckooFilter;
import abe.access_structure.matrix.LSSSMatrix;
import abe.keys.C_ABE;
import abe.keys.PublicKey;
import abe.keys.Signature;
import abe.keys.que1.Query1;
import abe.keys.que2.Q2Set;
import abe.keys.que2.Query2;
import abe.keys.res1.Response1;
import abe.keys.res2.Response2;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.ElementPowPreProcessing;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.List;

public class TeleServiceProvider {
    private static Pairing bp = PublicKey.bp;
    private static C_ABE c_abe;
    private static CuckooFilter filter;
    private static LSSSMatrix matrix;

    public static void receiveCipherText(C_ABE c_abe, CuckooFilter filter, LSSSMatrix matrix){
        TeleServiceProvider.c_abe = c_abe;
        TeleServiceProvider.filter = filter;
        TeleServiceProvider.matrix = matrix;
    }

    public static Response1 nameQuery(Query1 Q1){
        List<String> fingerprints = Q1.fingerprints;

        List<Integer> rows = filter.searchFingerprints(fingerprints);
        List<String> retFingerprints = matrix.returnFingerprints(rows);

        return c_abe.getResponse1(retFingerprints);
    }

    public static Response2 spanQuery(Query2 Q2){
        List<Q2Set> q2Sets = Q2.sets;
        Signature signature = Q2.signature;
        Element L_3 = Q2.L_3;

        if(verifySignature(signature, L_3)){
            List<Integer> rows = filter.searchSpans(q2Sets, L_3);
            List<String> retFingerprints = matrix.returnFingerprints(rows);

            return c_abe.getResponse2(retFingerprints);
        }

        return null;
    }

    private static boolean verifySignature(Signature signature, Element L_3){
        Field Zr = PublicKey.Zr;
        Element g_sigmaX = PublicKey.g_sigmaX;
        Element g_sigmaY = PublicKey.g_sigmaY;
        ElementPowPreProcessing g_sigma = PublicKey.g_sigma;
        Element t__ = signature.getT__();
        Element h_sigma = PublicKey.H_sigma(L_3);

        Element pair = bp.pairing(signature.getSigma(), (g_sigmaX.getImmutable()).mul(g_sigma.powZn(h_sigma)).mul(g_sigmaY.powZn(t__))).getImmutable();
        return pair.isEqual(bp.pairing(g_sigma.powZn(Zr.newElement(1)), g_sigma.powZn(Zr.newElement(1))));
    }
}
