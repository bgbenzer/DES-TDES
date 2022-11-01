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

    private byte[] inputText;
    private String key;
    private String IV;
    private String nonce;
    private SecretKey secretKey;


    public Ciphers(byte[] inputText, String key, String IV, String nonce) throws NoSuchAlgorithmException, InvalidKeySpecException {
        this.inputText = inputText;
        this.key = key;
        this.IV = IV;
        this.nonce = nonce;
    }
    public Ciphers() {

    }

    public byte[] CBCEncryption(String op) throws Exception {
        byte[] plainText = getInputText();

        List<Byte> cipherTextList = new ArrayList<>(); // final cipher text

        SecretKey iv8byte = keyGen(op,(op.equals("DES"))? 64:192, getIV()); // obtaining IV
        byte[] iv = iv8byte.getEncoded();

        byte[] f64Bit = new byte[8]; // first 64 bits
        f64Bit = xOR(plainText,iv);

        byte[] secondaryIV = encrypt(op, f64Bit); // first output (encryption with iv)
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
                secondaryIV = encrypt(op, newCT); // change previous cipher text as new ones output

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
    public byte[] CBCDecryption(String op) throws Exception {

        byte[] cipherText = getInputText();
        List<Byte> plainTextList = new ArrayList<>(); // final plain text

        SecretKey secretKey = keyGen(op,(op.equals("DES"))? 64:192, getIV()); // obtaining 64 bit IV
        byte[] iv = secretKey.getEncoded();

        byte[] first64BitCipherText = new byte[8]; // first 64 bits
        first64BitCipherText = Arrays.copyOfRange(cipherText, 0, 8);

        byte[] plainTextBeforeXORed = decrypt(op, first64BitCipherText); // first output (encryption with iv)
        byte[] plainText = xOR(plainTextBeforeXORed,iv);

        for (int k = 0; k <plainText.length ; k++) {
            plainTextList.add(plainText[k]);
        }

        int counter = 0;
        byte[] rest64BitCipherText = new byte[8];

        for (int i = 8; i < cipherText.length; i++) {
            if(counter == 7){ // take next 8 byte
                rest64BitCipherText[counter] = cipherText[i];
                plainTextBeforeXORed = decrypt(op, rest64BitCipherText); // change previous cipher text as new ones output

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

    public byte[] CFBEncryption(String op) throws Exception {
        byte[] plainText = getInputText();

        List<Byte> cipherTextList = new ArrayList<>(); // final cipher text

        SecretKey secretKey = keyGen(op,(op.equals("DES"))? 64:198, getIV()); // obtaining 64 bit IV
        byte[] iv = secretKey.getEncoded();

        byte[] ivEncrypt = encrypt(op, iv);

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
                byte[] cipherTextEncrypt = encrypt(op, cipherText);
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
    public byte[] CFBDecryption(String op) throws Exception {

        byte[] cipherText = getInputText();
        List<Byte> plainTextList = new ArrayList<>(); // final plain text

        SecretKey secretKey = keyGen(op,(op.equals("DES"))? 64:198, getIV()); // obtaining 64 bit IV
        byte[] iv = secretKey.getEncoded();

        byte[] ivEncrypt = encrypt(op, iv);

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

                byte[] cipherTextEncrypt = encrypt(op, first64BitCipherText); // change previous cipher text as new ones output

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

    public byte[] OFBEncryption(String op) throws Exception {
        byte[] plainText = getInputText();

        List<Byte> cipherTextList = new ArrayList<>(); // final cipher text

        SecretKey secretKey = keyGen(op,(op.equals("DES"))? 64:198, getIV()); // obtaining 64 bit IV
        byte[] iv = secretKey.getEncoded();

        byte[] ivEncrypt = encrypt(op, iv);

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
                ivEncrypt = encrypt(op, ivEncrypt);
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
    public byte[] OFBDecryption(String op) throws Exception {

        byte[] cipherText = getInputText();
        List<Byte> plainTextList = new ArrayList<>(); // final plain text

        SecretKey secretKey = keyGen(op,(op.equals("DES"))? 64:198, getIV()); // obtaining 64 bit IV
        byte[] iv = secretKey.getEncoded();

        byte[] ivEncrypt = encrypt(op, iv);

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
                ivEncrypt = encrypt(op, ivEncrypt); // change previous cipher text as new ones output

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

    public byte[] CTREncryptionAndDecryption( String op) throws Exception {

        byte[] plainText = getInputText();
        List<Byte> cipherTextList = new ArrayList<>(); // final cipher text

        long counterForEncryption = 0;
        SecretKey nonce8byte = keyGen(op,(op.equals("DES"))? 64:198, getNonce()); // obtaining 64 bit Nonce
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
                byte[] nonceBytes = getNonce().getBytes();
                byte[] nonceConcatCounter = new byte[counterForEncryptionArray.length+nonceBytes.length];

                System.arraycopy(nonceBytes, 0, nonceConcatCounter, 0, nonceBytes.length);
                System.arraycopy(counterForEncryptionArray, 0, nonceConcatCounter, nonceBytes.length, counterForEncryptionArray.length);

                SecretKey nonceCounter = keyGen(op,(op.equals("DES"))? 64:198, new String(counterForEncryptionArray));
                byte[] nonceAndCounter = nonceCounter.getEncoded();

                byte[] EncryptedNonceAndCounter = encrypt(op, nonceAndCounter);
                byte[] XoredEncryptionAndPlainText = xOR(EncryptedNonceAndCounter, plain64Bit);

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


    public byte[] getInputText() {
        return inputText;
    }

    public void setInputText(byte[] inputText) {
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
