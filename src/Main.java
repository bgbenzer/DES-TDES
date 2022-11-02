import java.nio.ByteBuffer;

public class Main {

    public static void main(String[] args) throws Exception {

        //        FileCipher −e −i text.txt −o output.txt DES CFD key.txt
        String[] plainTextFile = {};
        byte[] cipherTextFile = new byte[0];

        String[] keyFile = Operations.readFile(args[8]); // reading keys from file

        if(args[1].equals("-e")){
            plainTextFile = Operations.readFile(args[3]); // reading plaintext from file
        }
        else if(args[1].equals("-d")){
            cipherTextFile = Operations.readAsByte(args[3]);
        }



        String[] keys = keyFile[0].split("-"); // Splitting keys based on "-"


        byte[] encryptedOrDecrypted = new byte[0];

        long startTime = 0;
        if(args[6].equals("DES")){
            DES des = new DES( (args[1].equals("-e"))? plainTextFile[0].getBytes():cipherTextFile,keys[1],keys[0], keys[2]);

            switch(args[7]){

                case "CBC":
                    if(args[1].equals("-e")){
                        startTime = System.currentTimeMillis();
                        encryptedOrDecrypted = des.CBCEncryption("DES");
                    }else if (args[1].equals("-d")){
                        startTime = System.currentTimeMillis();
                        encryptedOrDecrypted = des.CBCDecryption("DES");
                    }
                    break;
                case "CFB":
                    if(args[1].equals("-e")){
                        startTime = System.currentTimeMillis();
                        encryptedOrDecrypted = des.CFBEncryption("DES");
                    }else if (args[1].equals("-d")){
                        startTime = System.currentTimeMillis();
                        encryptedOrDecrypted = des.CFBDecryption("DES");
                    }
                    break;
                case "OFB":
                    if(args[1].equals("-e")){
                        startTime = System.currentTimeMillis();
                        encryptedOrDecrypted = des.OFBEncryption("DES");
                    }else if (args[1].equals("-d")){
                        startTime = System.currentTimeMillis();
                        encryptedOrDecrypted = des.OFBDecryption("DES");
                    }
                    break;
                case "CTR":
                    startTime = System.currentTimeMillis();
                    encryptedOrDecrypted = des.CTREncryptionAndDecryption("DES");
                    break;
            }
            long finishTime = System.currentTimeMillis();
            long timeDiff = finishTime-startTime;

            if(args[1].equals("-e")){
                    Operations.writeAsByte(encryptedOrDecrypted, args[5]);
            }
            else if(args[1].equals("-d")){
                char[] finalData =  new String(encryptedOrDecrypted).toCharArray();
                String finalString = "";
                for(char c: finalData){
                    if(c != '\u0000'){
                        finalString = finalString+c;
                    }
                }
                Operations.writeToFile(finalString, args[5]);
            }

            Operations.writeToFile(args[3]+ " "+ args[5]+ " "+ ((args[1].equals("-e"))? "enc": "dec")+" "+args[6]+" "+args[7]+ " "+ timeDiff ,"run.log");

        }

        else if (args[6].equals("3DES")){
            TripleDES tripleDES = new TripleDES((args[1].equals("-e"))? plainTextFile[0].getBytes():cipherTextFile,keys[1],keys[0], keys[2]);

            switch(args[7]){

                case "CBC":
                    if(args[1].equals("-e")){
                        startTime = System.currentTimeMillis();
                        encryptedOrDecrypted = tripleDES.CBCEncryption("TripleDES");
                    }else if (args[1].equals("-d")){
                        startTime = System.currentTimeMillis();
                        encryptedOrDecrypted = tripleDES.CBCDecryption("TripleDES");
                    }
                break;
                case "CFB":
                    if(args[1].equals("-e")){
                        startTime = System.currentTimeMillis();
                        encryptedOrDecrypted = tripleDES.CFBEncryption("TripleDES");
                    }else if (args[1].equals("-d")){
                        startTime = System.currentTimeMillis();
                        encryptedOrDecrypted = tripleDES.CFBDecryption("TripleDES");
                    }
                    break;
                case "OFB":
                    if(args[1].equals("-e")){
                        startTime = System.currentTimeMillis();
                        encryptedOrDecrypted = tripleDES.OFBEncryption("TripleDES");
                    }else if (args[1].equals("-d")){
                        startTime = System.currentTimeMillis();
                        encryptedOrDecrypted = tripleDES.OFBDecryption("TripleDES");
                    }
                break;
                case "CTR":
                    startTime = System.currentTimeMillis();
                    encryptedOrDecrypted = tripleDES.CTREncryptionAndDecryption("TripleDES");
                break;
            }
            long finishTime = System.currentTimeMillis();
            long timeDiff = finishTime-startTime;
            if(args[1].equals("-e")){
                Operations.writeAsByte(encryptedOrDecrypted, args[5]);
            }
            else if(args[1].equals("-d")){
                char[] finalData =  new String(encryptedOrDecrypted).toCharArray();
                String finalString = "";
                for(char c: finalData){
                    if(c != '\u0000'){
                        finalString = finalString+c;
                    }
                }
                Operations.writeToFile(finalString, args[5]);
            }
            Operations.writeToFile(args[3]+ " "+ args[5]+ " "+ ((args[1].equals("-e"))? "enc": "dec")+" "+args[6]+" "+args[7]+ " "+ timeDiff ,"run.log");



        }



    }

}
