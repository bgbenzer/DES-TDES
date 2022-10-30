import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class DES extends Ciphers{

    public DES(String inputText, String key, String IV, String nonce) throws NoSuchAlgorithmException, InvalidKeySpecException {
        super(inputText,key,IV,nonce);
        this.setSecretKey(super.keyGen("DES",64, key));
    }


    public byte[] CBCEncryption() throws Exception {
        byte[] plainText = getInputText().getBytes();

        List<Byte> cipherTextList = new ArrayList<>(); // final cipher text

        SecretKey iv8byte = keyGen("DES",64, getIV()); // obtaining 64 bit IV
        byte[] iv = iv8byte.getEncoded();

        byte[] f64Bit = new byte[8]; // first 64 bits
        f64Bit = xOR(plainText,iv);

        byte[] secondaryIV = encrypt("DES", f64Bit); // first output (encryption with iv)
        for (int k = 0; k <secondaryIV.length ; k++) {
            cipherTextList.add(secondaryIV[k]);
        }

        int counter = 0;
        byte[] r64Bit = new byte[8];

        int len = plainText.length;
        int mod = len%8;
        len = (mod==0)? len: len+8-mod;

        for (int i = 8; i < len; i++) {
            if(counter == 7){ // take next 8 byte
                r64Bit[counter] = (i<plainText.length)? plainText[i]:(0);
                byte[] newCT = xOR(r64Bit,secondaryIV); //Xor with previous cipher text
                secondaryIV = encrypt("DES", newCT); // change previous cipher text as new ones output

                for (int k = 0; k <secondaryIV.length ; k++) { // add new bytes to total cipher text
                    cipherTextList.add(secondaryIV[k]);
                }
                counter = 0;
            }
            else{

                r64Bit[counter] = (i<plainText.length)? plainText[i]:(0);

                counter++;
            }
        }

        Byte[] ft = cipherTextList.toArray(new Byte[0]);
        byte[] finalCT = new byte[ft.length];
        for (int l = 0; l < ft.length ; l++) {
            finalCT[l] = ft[l].byteValue();
        }

        return finalCT;
    }

    public byte[] CBCDecryption(byte[] cipherText) throws Exception {
        List<Byte> plainTextList = new ArrayList<>(); // final plain text

        SecretKey secretKey = keyGen("DES",64, getIV()); // obtaining 64 bit IV
        byte[] iv = secretKey.getEncoded();

        byte[] first64BitCipherText = new byte[8]; // first 64 bits
        first64BitCipherText = Arrays.copyOfRange(cipherText, 0, 8);

        byte[] plainTextBeforeXORed = decrypt("DES", first64BitCipherText); // first output (encryption with iv)
        byte[] plainText = xOR(plainTextBeforeXORed,iv);

        for (int k = 0; k <plainText.length ; k++) {
            plainTextList.add(plainText[k]);
        }

        int counter = 0;
        byte[] rest64BitCipherText = new byte[8];

        for (int i = 8; i < cipherText.length; i++) {
            if(counter == 7){ // take next 8 byte
                rest64BitCipherText[counter] = cipherText[i];
                plainTextBeforeXORed = decrypt("DES", rest64BitCipherText); // change previous cipher text as new ones output

                plainText = xOR(plainTextBeforeXORed,first64BitCipherText); //Xor with previous cipher text

                for (int j = 0; j < 8; j++) {
                    first64BitCipherText[j] = rest64BitCipherText[j];
                }

                for (int k = 0; k <plainText.length ; k++) { // add new bytes to total cipher text
                    plainTextList.add(plainText[k]);
                }
                counter = 0;
            }
            else{
                rest64BitCipherText[counter] = cipherText[i];

                counter++;
            }
        }

        Byte[] ft = plainTextList.toArray(new Byte[0]);
        byte[] finalCT = new byte[ft.length];
        for (int l = 0; l < ft.length ; l++) {
            finalCT[l] = ft[l].byteValue();
        }

        return finalCT;
    }

    public byte[] CFBEncryption() throws Exception {
        byte[] plainText = getInputText().getBytes();

        List<Byte> cipherTextList = new ArrayList<>(); // final cipher text

        SecretKey secretKey = keyGen("DES",64, getIV()); // obtaining 64 bit IV
        byte[] iv = secretKey.getEncoded();

        byte[] ivEncrypt = encrypt("DES", iv);

        byte[] first64BitPlainText = Arrays.copyOfRange(plainText, 0, 8);

        byte[] cipherText = xOR(first64BitPlainText,ivEncrypt);

        for (int k = 0; k <cipherText.length ; k++) {
            cipherTextList.add(cipherText[k]);
        }

        int counter = 0;
        byte[] rest64BitPlainText = new byte[8];

        int len = plainText.length;
        int mod = len%8;
        len = (mod==0)? len: len+8-mod;

        for (int i = 8; i < len; i++) {
            if(counter == 7){ // take next 8 byte
                rest64BitPlainText[counter] = (i<plainText.length) ? plainText[i] : 0;
                byte[] cipherTextEncrypt = encrypt("DES", cipherText);
                cipherText = xOR(cipherTextEncrypt,rest64BitPlainText); //Xor with previous cipher text

                for (int k = 0; k <cipherText.length ; k++) { // add new bytes to total cipher text
                    cipherTextList.add(cipherText[k]);
                }
                counter = 0;
            }
            else{

                rest64BitPlainText[counter] = (i<plainText.length)? plainText[i]:(0);

                counter++;
            }
        }

        Byte[] ft = cipherTextList.toArray(new Byte[0]);
        byte[] finalCipherText = new byte[ft.length];
        for (int l = 0; l < ft.length ; l++) {
            finalCipherText[l] = ft[l].byteValue();
        }

        return finalCipherText;
    }

    public byte[] CFBDecryption(byte[] cipherText) throws Exception {
        List<Byte> plainTextList = new ArrayList<>(); // final plain text

        SecretKey secretKey = keyGen("DES",64, getIV()); // obtaining 64 bit IV
        byte[] iv = secretKey.getEncoded();

        byte[] ivEncrypt = encrypt("DES", iv);

        byte[] first64BitCipherText = new byte[8]; // first 64 bits
        first64BitCipherText = Arrays.copyOfRange(cipherText, 0, 8);

        byte[] plainText = xOR(first64BitCipherText,ivEncrypt);

        for (int k = 0; k <plainText.length ; k++) {
            plainTextList.add(plainText[k]);
        }

        int counter = 0;
        byte[] rest64BitCipherText = new byte[8];

        for (int i = 8; i < cipherText.length; i++) {
            if(counter == 7){ // take next 8 byte
                rest64BitCipherText[counter] = cipherText[i];

                byte[] cipherTextEncrypt = encrypt("DES", first64BitCipherText); // change previous cipher text as new ones output

                plainText = xOR(cipherTextEncrypt,rest64BitCipherText); //Xor with previous cipher text

                for (int j = 0; j < 8; j++) {
                    first64BitCipherText[j] = rest64BitCipherText[j];
                }

                for (int k = 0; k <plainText.length ; k++) { // add new bytes to total cipher text
                    plainTextList.add(plainText[k]);
                }
                counter = 0;
            }
            else{
                rest64BitCipherText[counter] = cipherText[i];

                counter++;
            }
        }

        Byte[] ft = plainTextList.toArray(new Byte[0]);
        byte[] finalCT = new byte[ft.length];
        for (int l = 0; l < ft.length ; l++) {
            finalCT[l] = ft[l].byteValue();
        }

        return finalCT;
    }

    public byte[] OFBEncryption() throws Exception {
        byte[] plainText = getInputText().getBytes();

        List<Byte> cipherTextList = new ArrayList<>(); // final cipher text

        SecretKey secretKey = keyGen("DES",64, getIV()); // obtaining 64 bit IV
        byte[] iv = secretKey.getEncoded();

        byte[] ivEncrypt = encrypt("DES", iv);

        byte[] first64BitPlainText = Arrays.copyOfRange(plainText, 0, 8);

        byte[] cipherText = xOR(first64BitPlainText,ivEncrypt);

        for (int k = 0; k <cipherText.length ; k++) {
            cipherTextList.add(cipherText[k]);
        }

        int counter = 0;
        byte[] rest64BitPlainText = new byte[8];

        int len = plainText.length;
        int mod = len%8;
        len = (mod==0)? len: len+8-mod;

        for (int i = 8; i < len; i++) {
            if(counter == 7){ // take next 8 byte
                rest64BitPlainText[counter] = (i<plainText.length) ? plainText[i] : 0;
                ivEncrypt = encrypt("DES", ivEncrypt);
                cipherText = xOR(rest64BitPlainText,ivEncrypt); //Xor with previous cipher text

                for (int k = 0; k <cipherText.length ; k++) { // add new bytes to total cipher text
                    cipherTextList.add(cipherText[k]);
                }
                counter = 0;
            }
            else{

                rest64BitPlainText[counter] = (i<plainText.length)? plainText[i]:(0);

                counter++;
            }
        }

        Byte[] ft = cipherTextList.toArray(new Byte[0]);
        byte[] finalCipherText = new byte[ft.length];
        for (int l = 0; l < ft.length ; l++) {
            finalCipherText[l] = ft[l].byteValue();
        }

        return finalCipherText;
    }

    public byte[] OFBDecryption(byte[] cipherText) throws Exception {
        List<Byte> plainTextList = new ArrayList<>(); // final plain text

        SecretKey secretKey = keyGen("DES",64, getIV()); // obtaining 64 bit IV
        byte[] iv = secretKey.getEncoded();

        byte[] ivEncrypt = encrypt("DES", iv);

        byte[] first64BitCipherText = new byte[8]; // first 64 bits
        first64BitCipherText = Arrays.copyOfRange(cipherText, 0, 8);

        byte[] plainText = xOR(first64BitCipherText,ivEncrypt);

        for (int k = 0; k <plainText.length ; k++) {
            plainTextList.add(plainText[k]);
        }

        int counter = 0;
        byte[] rest64BitCipherText = new byte[8];

        for (int i = 8; i < cipherText.length; i++) {
            if(counter == 7){ // take next 8 byte
                rest64BitCipherText[counter] = cipherText[i];
                ivEncrypt = encrypt("DES", ivEncrypt); // change previous cipher text as new ones output

                plainText = xOR(ivEncrypt,rest64BitCipherText); //Xor with previous cipher text

                for (int k = 0; k <plainText.length ; k++) { // add new bytes to total cipher text
                    plainTextList.add(plainText[k]);
                }
                counter = 0;
            }
            else{
                rest64BitCipherText[counter] = cipherText[i];

                counter++;
            }
        }

        Byte[] ft = plainTextList.toArray(new Byte[0]);
        byte[] finalCT = new byte[ft.length];
        for (int l = 0; l < ft.length ; l++) {
            finalCT[l] = ft[l].byteValue();
        }

        return finalCT;
    }

    byte[] toBytes(long i) {
        byte[] result = new byte[8];

        result[0] = (byte) (i >> 56);
        result[1] = (byte) (i >> 48);
        result[2] = (byte) (i >> 40);
        result[3] = (byte) (i >> 32);
        result[4] = (byte) (i >> 24);
        result[5] = (byte) (i >> 16);
        result[6] = (byte) (i >> 8);
        result[7] = (byte) (i /*>> 0*/);

        return result;
    }

    public byte[] CTREncryptionAndDecryption(byte[] text) throws Exception {
        byte[] plainText = text;
        List<Byte> cipherTextList = new ArrayList<>(); // final cipher text

        long counterForEncryption = 0;
        SecretKey nonce8byte = keyGen("DES",64, getNonce()); // obtaining 64 bit Nonce
        byte[] nonce = nonce8byte.getEncoded();

        byte[] plain64Bit = new byte[8];

        int len = plainText.length;
        int mod = len%8;
        len = (mod==0)? len: len+8-mod;

        int counter = 0;
        for (int i = 0; i < len; i++){
            if(counter == 7){
                plain64Bit[counter] = (i < plainText.length) ? plainText[i] : 0;
                byte[] counterForEncryptionArray = toBytes(counterForEncryption);
                byte[] XoredNonceAndCounter = xOR(nonce, counterForEncryptionArray);
                byte[] EncryptedNonceAndCounter = encrypt("DES", XoredNonceAndCounter);
                byte[] XoredEncryptionAndPlainText = xOR(EncryptedNonceAndCounter, nonce);

                for (int k = 0; k <XoredEncryptionAndPlainText.length ; k++) {
                    cipherTextList.add(XoredEncryptionAndPlainText[k]);
                }
                counterForEncryption++;
                counter = 0;
            }
            else {
                plain64Bit[counter] = (i < plainText.length) ? plainText[i] : 0;

                counter++;
            }
        }

        Byte[] ft = cipherTextList.toArray(new Byte[0]);
        byte[] finalCT = new byte[ft.length];
        for (int l = 0; l < ft.length ; l++) {
            finalCT[l] = ft[l].byteValue();
        }

        return finalCT;
    }






}
