import sun.security.util.ArrayUtil;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

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

    public SecretKey keyGen(String op, int keySize) throws NoSuchAlgorithmException, InvalidKeySpecException {

        byte[] keyBytes = key.getBytes();
        byte[] saltKey = new byte[keySize/8];
        saltKey = Arrays.copyOfRange(keyBytes,0,8);
        ArrayUtil.reverse(saltKey);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(key.toCharArray(), saltKey, 65536, keySize);

        SecretKey secretKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(),op);
        return secretKey;
    }


    public byte[] Encrypt(String op) throws Exception {

        byte[] plainText = inputText.getBytes();
        Cipher cipher = Cipher.getInstance((op+"/ECB/PKCS5Padding"));

        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] cipherText = cipher.doFinal(plainText);

        return cipherText;
    }

    public String Decrypt(byte[] inputText,String op) throws Exception {

        byte[] cipherText = inputText;
        Cipher cipher = Cipher.getInstance((op+"/ECB/PKCS5Padding"));

        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] plainText = cipher.doFinal(cipherText);

        return new String(plainText);
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
