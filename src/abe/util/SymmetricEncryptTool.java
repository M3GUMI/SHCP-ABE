package abe.util;

import it.unisa.dia.gas.jpbc.Element;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.security.Key;

public class SymmetricEncryptTool {
    /**
     * 获取随机AES对称密钥
     * @return AES对称密钥
     */
    public static byte[] getPSE(){
        byte[] bytesKey;

        KeyGenerator keyGenerator = null;
        try {
            keyGenerator = KeyGenerator.getInstance("DES");
        } catch (Exception e) {
            e.printStackTrace();
        }

        keyGenerator.init(56);  //DES密钥为56位
        SecretKey secretKey = keyGenerator.generateKey();
        bytesKey = secretKey.getEncoded();

        return bytesKey;
    }


    /**
     * 加密明文
     * @param text 明文
     * @param key AES对称密钥
     * @return 密文
     */
    public static byte[] encryptText(byte[] text, Element key){
        byte[] buffer = key.toBytes();
        byte[] PSE = new byte[8];
        for (int i = 0; i < 8; i++) {
            PSE[i] = buffer[i];
        }

        // KEY转换
        byte[] cipherText = new byte[0]; //clear_text是用getBytes()直接得到的，result即密文
        try {
            DESKeySpec desKeySpec = new DESKeySpec(PSE);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
            Key convertSecretKey = factory.generateSecret(desKeySpec);


            // 加密（加解密方式：..工作模式/填充方式）
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding"); //初始化
            cipher.init(Cipher.ENCRYPT_MODE, convertSecretKey);
            cipherText = cipher.doFinal(text);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return cipherText;
    }


    /**
     * 解密密文
     * @param cipherText 密文
     * @param key AES对称密钥
     * @return 明文
     */
    public static byte[] decryptCipherText(byte[] cipherText, Element key){
        byte[] buffer = key.toBytes();
        byte[] PSE = new byte[8];
        for (int i = 0; i < 8; i++) {
            PSE[i] = buffer[i];
        }

        byte[] text = null;
        try {
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding"); //初始化

            // KEY转换
            DESKeySpec desKeySpec = new DESKeySpec(PSE);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
            Key convertSecretKey = factory.generateSecret(desKeySpec);

            // 解密
            cipher.init(Cipher.DECRYPT_MODE, convertSecretKey);
            text = cipher.doFinal(cipherText);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return text;
    }
}
