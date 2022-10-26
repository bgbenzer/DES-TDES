import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

public class Main {

    public static void main(String[] args) throws Exception {

        String[] keyFile = Operations.readFile("key.txt"); // reading keys from file
        String[] plainTextFile = Operations.readFile("text.txt"); // reading plaintext from file

        String[] keys = keyFile[0].split("-"); // Splitting keys based on "-"

//        long startTime = System.currentTimeMillis();
//        long finishTime = System.currentTimeMillis();
//        long timeDiff = finishTime-startTime;
//        Operations.writeToFile(args[3]+ " "+ args[5]+ " "+ ((args[1]== "-e")? "enc": "dec")+" "+args[6]+" "+args[7]+ " "+ timeDiff ,"run.log");

    CipherOps cipherOps = new CipherOps(plainTextFile[0], keys[1]);
        System.out.println(cipherOps.getKey());
        System.out.println(cipherOps.stringKey());
        System.out.println("====================================");
        System.out.println(cipherOps.stringKey().getBytes(StandardCharsets.UTF_8).length);
        for(byte i : cipherOps.stringKey().getBytes(StandardCharsets.UTF_8)){
            System.out.println(i);
        }


    }

}
