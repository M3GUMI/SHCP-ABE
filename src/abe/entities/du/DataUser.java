package abe.entities.du;

import abe.entities.aa.AttributeAuthority;
import abe.entities.dos.DataOwner;
import abe.entities.tsp.TeleServiceProvider;
import abe.keys.PublicKey;
import abe.keys.que1.Query1;
import abe.keys.que2.Q2Set;
import abe.keys.que2.Query2;
import abe.keys.res1.R1Set;
import abe.keys.res1.Response1;
import abe.keys.res2.R2Set;
import abe.keys.res2.Response2;
import abe.util.SymmetricEncryptTool;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.*;

public class DataUser {
    public AttributeSecretKey ask;
    public List<String> attributeNames;
    public List<String> fingerprints;

    public DataUser(List<AssignedAttribute> assignedAttributes){
        ask = AttributeAuthority.keyGen(assignedAttributes);
        attributeNames = new ArrayList<>();
        fingerprints = new ArrayList<>();

        for (AssignedAttribute assignedAttribute : assignedAttributes) {
            String attributeName = assignedAttribute.getAttributeName();
            String fingerprint = PublicKey.H_f(attributeName);

            attributeNames.add(attributeName);
            fingerprints.add(fingerprint);
        }
    }

    public Response1 query1(){
        return TeleServiceProvider.nameQuery(new Query1(fingerprints));
    }

    public byte[] query2(Response1 response1){
        Element P_P = policyDec(response1);
        Pairing bp = PublicKey.bp;
        Field Zr = PublicKey.Zr;
        Field GT = PublicKey.GT;
        Element lambda = PublicKey.lambda;
        Element mu = PublicKey.mu;

        List<Q2Set> q2Sets = new ArrayList<>();
        Map<String, Element> E_x1List = new HashMap<>();
        List<R1Set> sets = response1.sets;
        for (R1Set set : sets) {
            String policy = new String(SymmetricEncryptTool.decryptCipherText(set.c_i, P_P));
            String fingerprint = set.fingerprint;
            UserAttribute userAttribute = ask.getAttributeByFingerprint(fingerprint);

            if (policy.matches("[a-z,A-Z,0-9]*:[0-9]*-[0-9]*")) {
                int index1 = policy.indexOf(":");
                int index2 = policy.indexOf("-");

                Element ti = Zr.newElement(Integer.parseInt(policy.substring(index1 + 1, index2))).getImmutable();
                Element tj = Zr.newElement(Integer.parseInt(policy.substring(index2 + 1))).getImmutable();
                Element ta = Zr.newElement(userAttribute.getTa()).getImmutable();
                Element tb = Zr.newElement(userAttribute.getTb()).getImmutable();
                Element K_x2 = userAttribute.getKx2();
                Element K_x3 = userAttribute.getKx3();

                Element E_x1 = K_x2.powZn(lambda.powZn(tj.sub(ta)).mul(mu.powZn(tb.sub(ti))));
                Element E_x2 = K_x3.powZn(lambda.powZn(tj.sub(ta)).mul(mu.powZn(tb.sub(ti))));

                Q2Set q2Set = new Q2Set(fingerprint, E_x2);
                q2Sets.add(q2Set);
                E_x1List.put(fingerprint, E_x1);
            }
        }

        Response2 response2 = TeleServiceProvider.spanQuery(new Query2(ask.signature, ask.L_3, q2Sets));
        List<R2Set> r2Sets = response2.sets;
        Element e = GT.newOneElement().getImmutable();
        Element L_2 = ask.L_2;
        Element K = ask.K;
        Element C_2 = response2.C_2;
        Element C2 = response2.C2;
        byte[] C_SE = response2.C_SE;

        for (int i = 0; i < r2Sets.size(); i++) {
            R2Set set = r2Sets.get(i);
            String fingerprint = set.fingerprint;
            Element C_i2 = set.C_i2;
            Element D_i2 = set.D_i2;
            Element E_x1 = E_x1List.get(fingerprint);

            Element e1 = bp.pairing(C_i2, L_2).getImmutable();
            Element e2 = bp.pairing(D_i2, E_x1).getImmutable();
            e = e.mul(e1).mul(e2);
        }
        Element e_ = bp.pairing(C_2, K).getImmutable();
        Element CM = e_.div(e);
        Element P_SE = C2.div(CM);

        byte[] plaintext = SymmetricEncryptTool.decryptCipherText(C_SE, P_SE);

        return plaintext;
    }

    private Element policyDec(Response1 response1){
        List<R1Set> sets = response1.sets;

        Element C1 = response1.C1;
        Element C_1 = response1.C_1;
        Element K = ask.K;
        Element L_1 = ask.L_1;
        Pairing bp = PublicKey.bp;
        Field GT = PublicKey.GT;

        Element e = GT.newOneElement().getImmutable();
        for (R1Set set : sets) {
            Element C_i1 = set.C_i1;
            Element D_i1 = set.D_i1;
            String fingerprint = set.fingerprint;
            Element K_x1 = ask.getAttributeByFingerprint(fingerprint).getKx1();

            Element e1 = bp.pairing(C_i1, L_1).getImmutable();
            Element e2 = bp.pairing(D_i1, K_x1).getImmutable();
            e = e.mul(e1).mul(e2);
        }
        Element e_ = bp.pairing(C_1, K).getImmutable();
        Element C_M = e_.div(e);

        return C1.div(C_M);
    }

    public long nameMatchTime(){
        long startTime = System.currentTimeMillis();
        TeleServiceProvider.nameQuery(new Query1(fingerprints));
        long endTime = System.currentTimeMillis();

        return endTime-startTime;
    }

    public long queryGenTime(){
        long startTime = System.currentTimeMillis();
        new Query1(fingerprints);

        long endTime = System.currentTimeMillis();

        return endTime-startTime;
    }

    public long policyDecTime(Response1 response1){
        long startTime = System.currentTimeMillis();

        List<R1Set> sets = response1.sets;

        Element C1 = response1.C1;
        Element C_1 = response1.C_1;
        Element K = ask.K;
        Element L_1 = ask.L_1;
        Pairing bp = PublicKey.bp;
        Field GT = PublicKey.GT;

        Element e = GT.newOneElement().getImmutable();
        for (R1Set set : sets) {
            Element C_i1 = set.C_i1;
            Element D_i1 = set.D_i1;
            String fingerprint = set.fingerprint;
            Element K_x1 = ask.getAttributeByFingerprint(fingerprint).getKx1();

            Element e1 = bp.pairing(C_i1, L_1).getImmutable();
            Element e2 = bp.pairing(D_i1, K_x1).getImmutable();
            e = e.mul(e1).mul(e2);
        }
        Element e_ = bp.pairing(C_1, K).getImmutable();
        Element C_M = e_.div(e);
        Element P_P = C1.div(C_M);

        Field Zr = PublicKey.Zr;
        Element lambda = PublicKey.lambda;
        Element mu = PublicKey.mu;

        List<Q2Set> q2Sets = new ArrayList<>();
        Map<String, Element> E_x1List = new HashMap<>();
        List<R1Set> sets1 = response1.sets;
        for (R1Set set : sets1) {
            String policy = new String(SymmetricEncryptTool.decryptCipherText(set.c_i, P_P));
            String fingerprint = set.fingerprint;
            UserAttribute userAttribute = ask.getAttributeByFingerprint(fingerprint);

            if (policy.matches("[a-z,A-Z,0-9]*:[0-9]*-[0-9]*")) {
                int index1 = policy.indexOf(":");
                int index2 = policy.indexOf("-");

                Element ti = Zr.newElement(Integer.parseInt(policy.substring(index1 + 1, index2))).getImmutable();
                Element tj = Zr.newElement(Integer.parseInt(policy.substring(index2 + 1))).getImmutable();
                Element ta = Zr.newElement(userAttribute.getTa()).getImmutable();
                Element tb = Zr.newElement(userAttribute.getTb()).getImmutable();
                Element K_x2 = userAttribute.getKx2();
                Element K_x3 = userAttribute.getKx3();

                Element E_x1 = K_x2.powZn(lambda.powZn(tj.sub(ta)).mul(mu.powZn(tb.sub(ti))));
                Element E_x2 = K_x3.powZn(lambda.powZn(tj.sub(ta)).mul(mu.powZn(tb.sub(ti))));

                Q2Set q2Set = new Q2Set(fingerprint, E_x2);
                q2Sets.add(q2Set);
                E_x1List.put(fingerprint, E_x1);
            }
        }

        long endTime = System.currentTimeMillis();
        return endTime-startTime;
    }

    public long spanMatchTime(Response1 response1){
        Element P_P = policyDec(response1);
        Pairing bp = PublicKey.bp;
        Field Zr = PublicKey.Zr;
        Field GT = PublicKey.GT;
        Element lambda = PublicKey.lambda;
        Element mu = PublicKey.mu;

        List<Q2Set> q2Sets = new ArrayList<>();
        Map<String, Element> E_x1List = new HashMap<>();
        List<R1Set> sets = response1.sets;
        for (R1Set set : sets) {
            String policy = new String(SymmetricEncryptTool.decryptCipherText(set.c_i, P_P));
            String fingerprint = set.fingerprint;
            UserAttribute userAttribute = ask.getAttributeByFingerprint(fingerprint);

            if (policy.matches("[a-z,A-Z,0-9]*:[0-9]*-[0-9]*")) {
                int index1 = policy.indexOf(":");
                int index2 = policy.indexOf("-");

                Element ti = Zr.newElement(Integer.parseInt(policy.substring(index1 + 1, index2))).getImmutable();
                Element tj = Zr.newElement(Integer.parseInt(policy.substring(index2 + 1))).getImmutable();
                Element ta = Zr.newElement(userAttribute.getTa()).getImmutable();
                Element tb = Zr.newElement(userAttribute.getTb()).getImmutable();
                Element K_x2 = userAttribute.getKx2();
                Element K_x3 = userAttribute.getKx3();

                Element E_x1 = K_x2.powZn(lambda.powZn(tj.sub(ta)).mul(mu.powZn(tb.sub(ti))));
                Element E_x2 = K_x3.powZn(lambda.powZn(tj.sub(ta)).mul(mu.powZn(tb.sub(ti))));

                Q2Set q2Set = new Q2Set(fingerprint, E_x2);
                q2Sets.add(q2Set);
                E_x1List.put(fingerprint, E_x1);
            }
        }

        long startTime = System.currentTimeMillis();
        Response2 response2 = TeleServiceProvider.spanQuery(new Query2(ask.signature, ask.L_3, q2Sets));
        long endTime = System.currentTimeMillis();

        return endTime-startTime;
    }

    public long spanDecTime(Response1 response1){
        Element P_P = policyDec(response1);
        Pairing bp = PublicKey.bp;
        Field Zr = PublicKey.Zr;
        Field GT = PublicKey.GT;
        Element lambda = PublicKey.lambda;
        Element mu = PublicKey.mu;

        List<Q2Set> q2Sets = new ArrayList<>();
        Map<String, Element> E_x1List = new HashMap<>();
        List<R1Set> sets = response1.sets;
        for (R1Set set : sets) {
            String policy = new String(SymmetricEncryptTool.decryptCipherText(set.c_i, P_P));
            String fingerprint = set.fingerprint;
            UserAttribute userAttribute = ask.getAttributeByFingerprint(fingerprint);

            if (policy.matches("[a-z,A-Z,0-9]*:[0-9]*-[0-9]*")) {
                int index1 = policy.indexOf(":");
                int index2 = policy.indexOf("-");

                Element ti = Zr.newElement(Integer.parseInt(policy.substring(index1 + 1, index2))).getImmutable();
                Element tj = Zr.newElement(Integer.parseInt(policy.substring(index2 + 1))).getImmutable();
                Element ta = Zr.newElement(userAttribute.getTa()).getImmutable();
                Element tb = Zr.newElement(userAttribute.getTb()).getImmutable();
                Element K_x2 = userAttribute.getKx2();
                Element K_x3 = userAttribute.getKx3();

                Element E_x1 = K_x2.powZn(lambda.powZn(tj.sub(ta)).mul(mu.powZn(tb.sub(ti))));
                Element E_x2 = K_x3.powZn(lambda.powZn(tj.sub(ta)).mul(mu.powZn(tb.sub(ti))));

                Q2Set q2Set = new Q2Set(fingerprint, E_x2);
                q2Sets.add(q2Set);
                E_x1List.put(fingerprint, E_x1);
            }
        }

        Response2 response2 = TeleServiceProvider.spanQuery(new Query2(ask.signature, ask.L_3, q2Sets));

        long startTime = System.currentTimeMillis();
        List<R2Set> r2Sets = response2.sets;
        Element e = GT.newOneElement().getImmutable();
        Element L_2 = ask.L_2;
        Element K = ask.K;
        Element C_2 = response2.C_2;
        Element C2 = response2.C2;
        byte[] C_SE = response2.C_SE;

        for (int i = 0; i < r2Sets.size(); i++) {
            R2Set set = r2Sets.get(i);
            String fingerprint = set.fingerprint;
            Element C_i2 = set.C_i2;
            Element D_i2 = set.D_i2;
            Element E_x1 = E_x1List.get(fingerprint);

            Element e1 = bp.pairing(C_i2, L_2).getImmutable();
            Element e2 = bp.pairing(D_i2, E_x1).getImmutable();
            e = e.mul(e1).mul(e2);
        }
        Element e_ = bp.pairing(C_2, K).getImmutable();
        Element CM = e_.div(e);
        Element P_SE = C2.div(CM);

        byte[] plaintext = SymmetricEncryptTool.decryptCipherText(C_SE, P_SE);
        long endTime = System.currentTimeMillis();

        return endTime-startTime;
    }
}
