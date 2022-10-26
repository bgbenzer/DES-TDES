import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;


public class CipherOps {

    private String plainText;
    private String key;
    private Cipher encCipher;
    private Cipher decCipher;
    private SecretKey secretKey;

    public CipherOps(String plainText, String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        this.plainText = plainText;
        this.key = key;
        this.secretKey = keyGen();
    }

    public void DES() throws Exception {


    }

    public SecretKey keyGen() throws NoSuchAlgorithmException, InvalidKeySpecException {

        byte[] keyBytes = string2Byte(key);
        byte[] randomString = new byte[8];
        randomString = Arrays.copyOfRange(keyBytes,0,8);
        Collections.reverse(Arrays.asList(randomString));

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(key.toCharArray(), randomString, 65536,32);

        SecretKey secretKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(),"DES");
        return secretKey;
    }

    public String stringKey(){
        byte[] rawData = secretKey.getEncoded();
        String encodedKey = Base64.getEncoder().encodeToString(rawData);
        return encodedKey;
    }


    public static String byte2String(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public static byte[] string2Byte(String data) {
        return Base64.getDecoder().decode(data);
    }








    public String getPlainText() {
        return plainText;
    }

    public void setPlainText(String plainText) {
        this.plainText = plainText;
    }

    public String getKey() {
        return key;
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(SecretKey secretKey) {
        this.secretKey = secretKey;
    }

    public void setKey(String key) {
        this.key = key;
    }
}
