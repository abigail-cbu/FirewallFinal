package Firewall;

import org.apache.commons.codec.binary.Base64;

import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * Modified form of AESEncrypter from book
 */
public class AESEncrypter {

    public static final int IV_SIZE = 16;  // 128 bits
    public static final int KEY_SIZE = 16; // 128 bits
    public static final int BUFFER_SIZE = 1024; // 1KB

    Cipher CIPHER;
    SecretKey SECRET_KEY;
    AlgorithmParameterSpec ivSpec;
    byte[] buf = new byte[BUFFER_SIZE];
    byte[] ivBytes = new byte[IV_SIZE];

    private void initializeSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(KEY_SIZE * 8);
        SECRET_KEY = kg.generateKey();
    }

    public AESEncrypter() throws Exception {
        CIPHER = Cipher.getInstance("AES/CBC/PKCS5Padding");
    }

    public String encrypt(String key, String initVector, String value) throws Exception {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted = cipher.doFinal(value.getBytes());
            //System.out.println("encrypted string: " + Base64.encodeBase64String(encrypted));

            return Base64.encodeBase64String(encrypted);

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    public static String decrypt(String key, String initVector, String encrypted) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

            byte[] original = cipher.doFinal(Base64.decodeBase64(encrypted));

            return new String(original);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    public static byte[] createRandBytes(int numBytes)
            throws NoSuchAlgorithmException {
        byte[] bytesBuffer = new byte[numBytes];
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.nextBytes(bytesBuffer);
        return bytesBuffer;
    }

//    public static void main(String argv[]) throws Exception {
//        if (argv.length != 2)
//            usage();
//
//        String operation = argv[0];
//        String keyFile = argv[1];
//
//        if (operation.equals("createkey")) {
//        /* write key */
//            FileOutputStream fos = new FileOutputStream(keyFile);
//            KeyGenerator kg = KeyGenerator.getInstance("AES");
//            kg.init(KEY_SIZE * 8);
//            SecretKey skey = kg.generateKey();
//            fos.write(skey.getEncoded());
//            fos.close();
//        } else {
//	    /* read key */
//            byte keyBytes[] = new byte[KEY_SIZE];
//            FileInputStream fis = new FileInputStream(keyFile);
//            fis.read(keyBytes);
//            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
//
//	    /* initialize encrypter */
//            AESEncrypter aes = new AESEncrypter(keySpec);
//
//            if (operation.equals("encrypt")) {
//                aes.encrypt(System.in, System.out);
//            } else if (operation.equals("decrypt")) {
//                aes.decrypt(System.in, System.out);
//            } else {
//                usage();
//            }
//        }
//    }
//
//    public static void usage() {
//        System.err.println("java AESEncrypter createkey|encrypt|decrypt <keyfile>");
//        System.exit(-1);
//    }

}
