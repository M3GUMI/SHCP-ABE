package abe.entities.dos;

import abe.access_structure.AccessStructure;
import abe.access_structure.filter.CuckooFilter;
import abe.access_structure.matrix.LSSSMatrix;
import abe.access_structure.node.PolicyAttribute;
import abe.entities.tsp.TeleServiceProvider;
import abe.keys.C_ABE;
import abe.keys.ElementTest;
import abe.keys.PublicKey;
import abe.util.SymmetricEncryptTool;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.ElementPowPreProcessing;
import it.unisa.dia.gas.jpbc.Field;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DataOwner {
    public void Enc(String policy, String plaintext){
        AccessStructure accessStructure = AccessStructure.buildFromPolicy(policy);
        LSSSMatrix lsssMatrix = new LSSSMatrix(accessStructure);
        List<PolicyAttribute> policyAttributes = accessStructure.getAttributeList();

        Field GT = PublicKey.GT;
        Field Zr = PublicKey.Zr;

        ElementPowPreProcessing g = PublicKey.g;
        ElementPowPreProcessing omega = PublicKey.omega;
        Element lambda = PublicKey.lambda;
        Element mu = PublicKey.mu;
        Element Z = Zr.newElement(PublicKey.Z).getImmutable();
        Element gA = PublicKey.gA;
        Element eGGAlpha = PublicKey.eGGAlpha;
        Element eGOmegaAlpha = PublicKey.eGOmegaAlpha;

        Element PSE = GT.newRandomElement().getImmutable();
        Element P_P = GT.newRandomElement().getImmutable();
        List<List<Integer>> matrix = lsssMatrix.getMatrix();
        int l = matrix.size();
        int n = matrix.get(0).size();

        List<Element> yVector = new ArrayList<>();
        List<Element> y_Vector = new ArrayList<>();
        List<Element> rVector = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            yVector.add(Zr.newRandomElement().getImmutable());
            y_Vector.add(Zr.newRandomElement().getImmutable());
        }
        Element s = yVector.get(0);
        Element s_ = y_Vector.get(0);

        for (int i = 0; i < l; i++) {
            rVector.add(Zr.newRandomElement().getImmutable());
        }

        List<Element> gammaVector = new ArrayList<>();
        List<Element> gamma_Vector = new ArrayList<>();
        for (int i = 0; i < l; i++) {
            Element gamma = Zr.newZeroElement().getImmutable();
            Element gamma_ = Zr.newZeroElement().getImmutable();
            for (int j = 0; j < n; j++) {
                if(matrix.get(i).get(j)==1){
                    gamma = gamma.add(yVector.get(j));
                    gamma_ = gamma_.add(y_Vector.get(j));
                }
                if(matrix.get(i).get(j)==-1){
                    gamma = gamma.sub(yVector.get(j));
                    gamma_ = gamma_.sub(y_Vector.get(j));
                }
            }
            gammaVector.add(gamma);
            gamma_Vector.add(gamma_);
        }

        Element C1 = P_P.mul(eGGAlpha.powZn(s_));
        Element C2 = PSE.mul(eGOmegaAlpha.powZn(s));
        Element C_1 = g.powZn(s_).getImmutable();
        Element C_2 = omega.powZn(s).getImmutable();
        Map<String, Element> C1Map = new HashMap<>();
        Map<String, Element> C2Map = new HashMap<>();
        Map<String, Element> D1Map = new HashMap<>();
        Map<String, Element> D2Map = new HashMap<>();
        Map<String, byte[]> ciMap = new HashMap<>();

        for (int i = 0; i < l; i++) {
            PolicyAttribute policyAttribute = policyAttributes.get(i);
            String attributeName = policyAttribute.getAttributeName();
            String fingerprint = policyAttribute.getFingerprint();
            Element gamma_ = gamma_Vector.get(i);
            Element gamma = gammaVector.get(i);
            Element ri = rVector.get(i);
            ElementPowPreProcessing h = PublicKey.getHByName(attributeName);
            ElementPowPreProcessing h_ = PublicKey.getH_ByName(attributeName);
            Element t_i = Zr.newElement(policyAttribute.getTi()).getImmutable();
            Element t_j = Zr.newElement(policyAttribute.getTj()).getImmutable();

            Element C_i1 = (gA.powZn(gamma_)).mul(h.powZn(ri.mul(-1)).getImmutable());
            Element C_i2 = (gA.powZn(gamma)).mul(h_.powZn(ri.mul(-1).mul(lambda.powZn(t_j).mul(mu.powZn(Z.sub(t_i)))))).getImmutable();
            Element D_i1 = g.powZn(ri).getImmutable();
            Element D_i2 = omega.powZn(ri).getImmutable();
            byte[] ci = SymmetricEncryptTool.encryptText(policyAttribute.toString().getBytes(StandardCharsets.UTF_8), P_P);

            C1Map.put(fingerprint, C_i1);
            C2Map.put(fingerprint, C_i2);
            D1Map.put(fingerprint, D_i1);
            D2Map.put(fingerprint, D_i2);
            ciMap.put(fingerprint, ci);
        }

        byte[] ciphertext = SymmetricEncryptTool.encryptText(plaintext.getBytes(StandardCharsets.UTF_8), PSE);

        C_ABE c_abe = new C_ABE(ciphertext, C1, C2, C_1, C_2, C1Map, C2Map, D1Map, D2Map, ciMap);
        CuckooFilter filter = new CuckooFilter(accessStructure);

        TeleServiceProvider.receiveCipherText(c_abe, filter, lsssMatrix);

    }

    public long EncTime(String policy, String plaintext){
        long startTime = System.currentTimeMillis();

        AccessStructure accessStructure = AccessStructure.buildFromPolicy(policy);
        LSSSMatrix lsssMatrix = new LSSSMatrix(accessStructure);
        List<PolicyAttribute> policyAttributes = accessStructure.getAttributeList();

        Field GT = PublicKey.GT;
        Field Zr = PublicKey.Zr;

        ElementPowPreProcessing g = PublicKey.g;
        ElementPowPreProcessing omega = PublicKey.omega;
        Element lambda = PublicKey.lambda;
        Element mu = PublicKey.mu;
        Element Z = Zr.newElement(PublicKey.Z).getImmutable();
        Element gA = PublicKey.gA;
        Element eGGAlpha = PublicKey.eGGAlpha;
        Element eGOmegaAlpha = PublicKey.eGOmegaAlpha;

        Element PSE = GT.newRandomElement().getImmutable();
        Element P_P = GT.newRandomElement().getImmutable();
        List<List<Integer>> matrix = lsssMatrix.getMatrix();
        int l = matrix.size();
        int n = matrix.get(0).size();

        List<Element> yVector = new ArrayList<>();
        List<Element> y_Vector = new ArrayList<>();
        List<Element> rVector = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            yVector.add(Zr.newRandomElement().getImmutable());
            y_Vector.add(Zr.newRandomElement().getImmutable());
        }
        Element s = yVector.get(0);
        Element s_ = y_Vector.get(0);

        for (int i = 0; i < l; i++) {
            rVector.add(Zr.newRandomElement().getImmutable());
        }

        List<Element> gammaVector = new ArrayList<>();
        List<Element> gamma_Vector = new ArrayList<>();
        for (int i = 0; i < l; i++) {
            Element gamma = Zr.newZeroElement().getImmutable();
            Element gamma_ = Zr.newZeroElement().getImmutable();
            for (int j = 0; j < n; j++) {
                if(matrix.get(i).get(j)==1){
                    gamma = gamma.add(yVector.get(j));
                    gamma_ = gamma_.add(y_Vector.get(j));
                }
                if(matrix.get(i).get(j)==-1){
                    gamma = gamma.sub(yVector.get(j));
                    gamma_ = gamma_.sub(y_Vector.get(j));
                }
            }
            gammaVector.add(gamma);
            gamma_Vector.add(gamma_);
        }

        Element C1 = P_P.mul(eGGAlpha.powZn(s_));
        Element C2 = PSE.mul(eGOmegaAlpha.powZn(s));
        Element C_1 = g.powZn(s_).getImmutable();
        Element C_2 = omega.powZn(s).getImmutable();
        Map<String, Element> C1Map = new HashMap<>();
        Map<String, Element> C2Map = new HashMap<>();
        Map<String, Element> D1Map = new HashMap<>();
        Map<String, Element> D2Map = new HashMap<>();
        Map<String, byte[]> ciMap = new HashMap<>();

        for (int i = 0; i < l; i++) {
            PolicyAttribute policyAttribute = policyAttributes.get(i);
            String attributeName = policyAttribute.getAttributeName();
            String fingerprint = policyAttribute.getFingerprint();
            Element gamma_ = gamma_Vector.get(i);
            Element gamma = gammaVector.get(i);
            Element ri = rVector.get(i);
            ElementPowPreProcessing h = PublicKey.getHByName(attributeName);
            ElementPowPreProcessing h_ = PublicKey.getH_ByName(attributeName);
            Element t_i = Zr.newElement(policyAttribute.getTi()).getImmutable();
            Element t_j = Zr.newElement(policyAttribute.getTj()).getImmutable();

            Element C_i1 = (gA.powZn(gamma_)).mul(h.powZn(ri.mul(-1))).getImmutable();
            Element C_i2 = (gA.powZn(gamma)).mul(h_.powZn(ri.mul(-1).mul(lambda.powZn(t_j).mul(mu.powZn(Z.sub(t_i)))))).getImmutable();
            Element D_i1 = g.powZn(ri).getImmutable();
            Element D_i2 = omega.powZn(ri).getImmutable();
            byte[] ci = SymmetricEncryptTool.encryptText(policyAttribute.toString().getBytes(StandardCharsets.UTF_8), P_P);

            C1Map.put(fingerprint, C_i1);
            C2Map.put(fingerprint, C_i2);
            D1Map.put(fingerprint, D_i1);
            D2Map.put(fingerprint, D_i2);
            ciMap.put(fingerprint, ci);
        }

        byte[] ciphertext = SymmetricEncryptTool.encryptText(plaintext.getBytes(StandardCharsets.UTF_8), PSE);

        C_ABE c_abe = new C_ABE(ciphertext, C1, C2, C_1, C_2, C1Map, C2Map, D1Map, D2Map, ciMap);
        CuckooFilter filter = new CuckooFilter(accessStructure);

        TeleServiceProvider.receiveCipherText(c_abe, filter, lsssMatrix);

        long endTime = System.currentTimeMillis();

        return endTime-startTime;
    }
}
