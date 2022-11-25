package abe.access_structure.filter;


import abe.access_structure.AccessStructure;
import abe.access_structure.node.PolicyAttribute;
import abe.keys.PublicKey;
import abe.keys.que2.Q2Set;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class CuckooFilter {
    private int col = 47;
    private ArrayList<Entry[]> table;
    List<HashAlgorithm> hashAlgorithmList = new ArrayList<>();

    public CuckooFilter(AccessStructure accessStructure){
        TableInitiation();
        List<PolicyAttribute> attributeList = accessStructure.getAttributeList();
        
        insertAttributeList(attributeList);
    }

    private void TableInitiation(){
        table = new ArrayList<>();
        Random random = new Random();

        for (int i = 0; i < 3; i++) {
            table.add(new Entry[col]);
        }

        hashAlgorithmList.add(new HashAlgorithm(random.nextInt(17)));
        hashAlgorithmList.add(new HashAlgorithm(random.nextInt(23)));
        hashAlgorithmList.add(new HashAlgorithm(random.nextInt(31)));
    }


    private void insertAttributeList(List<PolicyAttribute> attributeList){
        for (PolicyAttribute policyAttribute : attributeList) {
            Entry entry = new Entry(policyAttribute);

            for (int i = 0; i < hashAlgorithmList.size(); i++) {
                HashAlgorithm hashAlgorithm = hashAlgorithmList.get(i);
                int colIndex = getIndex(hashAlgorithm.hashCode(policyAttribute.getFingerprint()));

                if(table.get(i)[colIndex]==null){
                    table.get(i)[colIndex] = entry;
                    break;
                }

                if(i==hashAlgorithmList.size()-1){
                    Random random = new Random();
                    hashAlgorithm = new HashAlgorithm(random.nextInt(40));
                    hashAlgorithmList.add(hashAlgorithm);
                    table.add(new Entry[col]);
                    colIndex = getIndex(hashAlgorithm.hashCode(policyAttribute.getFingerprint()));
                    table.get(i+1)[colIndex] = entry;
                }
            }
        }
    }

    private int searchFingerprint(String fingerprint){
        for (int i = 0; i < hashAlgorithmList.size(); i++) {
            HashAlgorithm hashAlgorithm = hashAlgorithmList.get(i);
            int colIndex = getIndex(hashAlgorithm.hashCode(fingerprint));

            Entry entry = table.get(i)[colIndex];
            if(entry != null && entry.getFingerprint().equals(fingerprint)){
                return entry.getRow();
            }
        }

        return -1;
    }

    public List<Integer> searchFingerprints(List<String> fingerprints){
        List<Integer> rows = new ArrayList<>();

        for (String fingerprint : fingerprints) {
            int row = searchFingerprint(fingerprint);
            if(row!=-1)
                rows.add(row);
        }

        return rows;
    }

    private int searchSpan(Q2Set set, Element L_3){
        String fingerprint = set.fingerprint;
        Element E_x2 = set.E_x2;

        for (int i = 0; i < hashAlgorithmList.size(); i++) {
            HashAlgorithm hashAlgorithm = hashAlgorithmList.get(i);
            int colIndex = getIndex(hashAlgorithm.hashCode(fingerprint));

            Entry entry = table.get(i)[colIndex];
            if(entry != null && entry.getFingerprint().equals(fingerprint)){
                Pairing bp = PublicKey.bp;
                Element S_i1 = entry.getS_1();
                Element S_i2 = entry.getS_2();

                Element element1 = bp.pairing(E_x2,S_i2).getImmutable();
                Element element2 = bp.pairing(S_i1, L_3).getImmutable();

                if (element1.mul(element2).isZero()){
                    return entry.getRow();
                }

                return -1;
            }
        }

        return -1;
    }

    public List<Integer> searchSpans(List<Q2Set> sets, Element L_3){
        List<Integer> rows = new ArrayList<>();

        for (Q2Set set : sets) {
            int row = searchSpan(set, L_3);
            if(row!=-1){
                rows.add(row);
            }
        }

        return rows;
    }

    private int getIndex(long hashCode) {
        if (hashCode % col < 0) {
            return (int) (hashCode % col) + col;
        }
        return (int) hashCode % col;
    }

    public void printFilter(){
        for (int i = 0; i < table.size(); i++) {
            for (int j = 0; j < table.get(0).length; j++) {
                if(table.get(i)[j]!=null)
                    printFilter();
            }
        }
    }
}
