import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class Ciphers {

    private String inputText;
    private String key;
    private String IV;
    private String nonce;
    private SecretKey secretKey;


    public Ciphers(String inputText, String key, String IV, String nonce) throws NoSuchAlgorithmException, InvalidKeySpecException {
        this.inputText = inputText;
        this.key = key;
        this.IV = IV;
        this.nonce = nonce;
    }
    public Ciphers() {

    }

    public SecretKey keyGen(String op, int keySize, String key) throws NoSuchAlgorithmException, InvalidKeySpecException {

        byte[] keyBytes = key.getBytes();
        byte[] saltKey = new byte[keySize/8];
        saltKey = Arrays.copyOfRange(keyBytes,0,8);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(key.toCharArray(), saltKey, 65536, keySize);

        SecretKey secretKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(),op);
        return secretKey;
    }


    public byte[] encrypt(String op, byte[] pT) throws Exception {

        Cipher cipher = Cipher.getInstance((op+"/ECB/NoPadding"));

        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] cipherText = cipher.doFinal(pT);

        return cipherText;
    }

    public byte[] decrypt(String op, byte[] cT) throws Exception {

        Cipher cipher = Cipher.getInstance((op+"/ECB/NoPadding"));

        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] plainText = cipher.doFinal(cT);

        return plainText;
    }

    public byte[] xOR(byte[] original, byte[] key){ // takes first 8 byte of original byte[] and Xor with key byte[]
        byte[] xORed = new byte[8];

        for(int i=0; i<8 ; i++){
            xORed[i] = (byte) (original[i] ^ key[i]);
        }

        return xORed;
    }


    public String getInputText() {
        return inputText;
    }

    public void setInputText(String inputText) {
        this.inputText = inputText;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getIV() {
        return IV;
    }

    public void setIV(String IV) {
        this.IV = IV;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(SecretKey secretKey) {
        this.secretKey = secretKey;
    }
}
