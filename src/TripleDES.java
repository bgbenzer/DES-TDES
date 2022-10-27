import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class TripleDES extends Ciphers {

    public TripleDES(String inputText, String key, String IV, String nonce) throws NoSuchAlgorithmException, InvalidKeySpecException {
        super(inputText,key,IV,nonce);
        this.setSecretKey(super.keyGen("TripleDES",112));
    }

}
