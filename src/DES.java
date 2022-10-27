import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class DES extends Ciphers{

    public DES(String inputText, String key, String IV, String nonce) throws NoSuchAlgorithmException, InvalidKeySpecException {
        super(inputText,key,IV,nonce);
        this.setSecretKey(super.keyGen("DES",64));
    }

}
