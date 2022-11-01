import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class DES extends Ciphers{

    public DES(byte[] inputText, String key, String IV, String nonce) throws NoSuchAlgorithmException, InvalidKeySpecException {
        super(inputText,key,IV,nonce);
        this.setSecretKey(super.keyGen("DES",64, key));
    }
}
