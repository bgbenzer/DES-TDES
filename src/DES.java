import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

public class DES extends Ciphers{

    public DES(String inputText, String key, String IV, String nonce) throws NoSuchAlgorithmException, InvalidKeySpecException {
        super(inputText,key,IV,nonce);
        this.setSecretKey(super.keyGen("DES",64, key));
    }


    public byte[] cbcENC() throws Exception {

        byte[] pT = getInputText().getBytes(); // plain text

        List<Byte> cT = new ArrayList<>(); // final cipher text

        SecretKey sKey = keyGen("DES",64, getIV()); // obtaining 64 bit IV
        byte[] iv = sKey.getEncoded();

        byte[] f64Bit = new byte[8]; // first 64 bits
        f64Bit = xOR(pT,iv);

        byte[] secondaryIV = encrypt("DES", f64Bit); // first output (encryption with iv)
        for (int k = 0; k <secondaryIV.length ; k++) {
            cT.add(secondaryIV[k]);
        }

        int counter = 0;
        byte[] r64Bit = new byte[8];

        int len = pT.length;
        int mod = len%8;
        len = (mod==0)? len: len+8-mod;

        for (int i = 8; i < len; i++) {

            if(counter == 7){ // take next 8 byte

                r64Bit[counter] = (i<pT.length)? pT[i]:(0);
                byte[] newCT = xOR(r64Bit,secondaryIV); //Xor with previous cipher text
                secondaryIV = encrypt("DES", newCT); // change previous cipher text as new ones output

                for (int k = 0; k <secondaryIV.length ; k++) { // add new bytes to total cipher text
                    cT.add(secondaryIV[k]);
                }
                counter = 0;
            }
            else{

                r64Bit[counter] = (i<pT.length)? pT[i]:(0);

                counter++;
            }
        }

        Byte[] ft = cT.toArray(new Byte[0]);
        byte[] finalCT = new byte[ft.length];
        for (int l = 0; l < ft.length ; l++) {
            finalCT[l] = ft[l].byteValue();
        }

        return finalCT;
    }

    public byte[] cbcDEC( byte[] c) throws Exception {

//        byte[] pT = getInputText().getBytes(); // plain text
        byte[] pT =c;
        List<Byte> cT = new ArrayList<>(); // final cipher text

        SecretKey sKey = keyGen("DES",64, getIV()); // obtaining 64 bit IV
        byte[] iv = sKey.getEncoded();

        byte[] f64Bit = new byte[8]; // first 64 bits

        byte[] secondaryIV = decrypt("DES", f64Bit); // first output (encryption with iv)
        secondaryIV = xOR(secondaryIV,iv);

        for (int k = 0; k <secondaryIV.length ; k++) {
            cT.add(secondaryIV[k]);
        }

        int counter = 0;
        byte[] r64Bit = new byte[8];

        int len = pT.length;
        int mod = len%8;
        len = (mod==0)? len: len+8-mod;

        for (int i = 8; i < len; i++) {

            if(counter == 7){ // take next 8 byte

                r64Bit[counter] = (i<pT.length)? pT[i]:(0);
                secondaryIV = decrypt("DES", r64Bit); // change previous cipher text as new ones output

                byte[] newCT = xOR(r64Bit,secondaryIV); //Xor with previous cipher text


                for (int k = 0; k <secondaryIV.length ; k++) { // add new bytes to total cipher text
                    cT.add(secondaryIV[k]);
                }
                counter = 0;
            }
            else{

                r64Bit[counter] = (i<pT.length)? pT[i]:(0);

                counter++;
            }
        }

        Byte[] ft = cT.toArray(new Byte[0]);
        byte[] finalCT = new byte[ft.length];
        for (int l = 0; l < ft.length ; l++) {
            finalCT[l] = ft[l].byteValue();
        }

        return finalCT;
    }




}
