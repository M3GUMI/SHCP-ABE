package abe.keys;

import abe.access_structure.node.PolicyAttribute;
import abe.keys.res1.R1Set;
import abe.keys.res1.Response1;
import abe.keys.res2.R2Set;
import abe.keys.res2.Response2;
import it.unisa.dia.gas.jpbc.Element;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class C_ABE {
    public byte[] C_SE;
    public Element C1;
    public Element C2;
    public Element C1_;
    public Element C2_;
    private Map<String, Element> Ci1Map;
    private Map<String, Element> Ci2Map;
    private Map<String, Element> Di1Map;
    private Map<String, Element> Di2Map;
    private Map<String, byte[]> ciMap;

    public C_ABE(byte[] c_se, Element c1, Element c2, Element c1_, Element c2_, Map<String, Element> ci1Map, Map<String, Element> ci2Map, Map<String, Element> di1Map, Map<String, Element> di2Map, Map<String, byte[]> ciMap) {
        C_SE = c_se;
        C1 = c1;
        C2 = c2;
        C1_ = c1_;
        C2_ = c2_;
        Ci1Map = ci1Map;
        Ci2Map = ci2Map;
        Di1Map = di1Map;
        Di2Map = di2Map;
        this.ciMap = ciMap;
    }

    public Element getCi1ByFingerprint(String fingerprint){
        return Ci1Map.get(fingerprint);
    }

    public Element getCi2ByFingerprint(String fingerprint){
        return Ci2Map.get(fingerprint);
    }

    public Element getDi1ByFingerprint(String fingerprint){
        return Di1Map.get(fingerprint);
    }

    public Element getDi2ByFingerprint(String fingerprint){
        return Di2Map.get(fingerprint);
    }

    public byte[] getCiByFingerprint(String fingerprint) {return ciMap.get(fingerprint);}

    public Response1 getResponse1(List<String> fingerprints){
        List<R1Set> sets = new ArrayList<>();

        for (String fingerprint : fingerprints) {
            byte[] ci = ciMap.get(fingerprint);
            Element D_i1 = Di1Map.get(fingerprint);
            Element C_i1 = Ci1Map.get(fingerprint);

            sets.add(new R1Set(D_i1, C_i1, ci, fingerprint));
        }

        return new Response1(C1, C1_, sets);
    }

    public Response2 getResponse2(List<String> fingerprints){
        List<R2Set> sets = new ArrayList<>();

        for (String fingerprint : fingerprints) {
            Element D_i2 = Di2Map.get(fingerprint);
            Element C_i2 = Ci2Map.get(fingerprint);

            sets.add(new R2Set(fingerprint, D_i2, C_i2));
        }

        return new Response2(C_SE, C2, C2_, sets);
    }
}
