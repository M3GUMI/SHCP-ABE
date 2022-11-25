package abe.access_structure.filter;

import java.io.Serializable;

/**
 * 哈希算法的类
 */
public class HashAlgorithm implements Serializable {
    private final int initNumber;

    public HashAlgorithm(int initNumber) {
        super();
        this.initNumber = initNumber;
    }


    public long hashCode(String key) {
        return (initNumber + key).hashCode();//传递进来的固定值 +key 模拟两个不同的 hashcode
    }
}
