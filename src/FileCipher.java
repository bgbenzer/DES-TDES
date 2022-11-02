import java.nio.ByteBuffer;

public class FileCipher {

    public static void main(String[] args) throws Exception {

        String[] plainTextFile = {};
        byte[] cipherTextFile = new byte[0];

        String[] keyFile = Operations.readFile(args[7]); // reading keys from file

        if(args[0].equals("-e")){
            plainTextFile = Operations.readFile(args[2]); // reading plaintext from file
        }
        else if(args[0].equals("-d")){
            cipherTextFile = Operations.readAsByte(args[2]);
        }



        String[] keys = keyFile[0].split("-"); // Splitting keys based on "-"


        byte[] encryptedOrDecrypted = new byte[0];

        long startTime = 0;
        if(args[5].equals("DES")){
            DES des = new DES( (args[0].equals("-e"))? plainTextFile[0].getBytes():cipherTextFile,keys[1],keys[0], keys[2]);

            switch(args[6]){

                case "CBC":
                    if(args[0].equals("-e")){
                        startTime = System.currentTimeMillis();
                        encryptedOrDecrypted = des.CBCEncryption("DES");
                    }else if (args[0].equals("-d")){
                        startTime = System.currentTimeMillis();
                        encryptedOrDecrypted = des.CBCDecryption("DES");
                    }
                    break;
                case "CFB":
                    if(args[0].equals("-e")){
                        startTime = System.currentTimeMillis();
                        encryptedOrDecrypted = des.CFBEncryption("DES");
                    }else if (args[0].equals("-d")){
                        startTime = System.currentTimeMillis();
                        encryptedOrDecrypted = des.CFBDecryption("DES");
                    }
                    break;
                case "OFB":
                    if(args[0].equals("-e")){
                        startTime = System.currentTimeMillis();
                        encryptedOrDecrypted = des.OFBEncryption("DES");
                    }else if (args[0].equals("-d")){
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

            if(args[0].equals("-e")){
                Operations.writeAsByte(encryptedOrDecrypted, Operations.directoryPath + args[4]);
            }
            else if(args[0].equals("-d")){
                char[] finalData =  new String(encryptedOrDecrypted).toCharArray();
                String finalString = "";
                for(char c: finalData){
                    if(c != '\u0000'){
                        finalString = finalString+c;
                    }
                }
                Operations.writeToFile(finalString, Operations.directoryPath + args[4]);
            }

            Operations.writeToFile(args[2]+ " " + Operations.directoryPath + args[4]+ " "+ ((args[0].equals("-e"))? "enc": "dec")+" "+args[5]+" "+args[6]+ " "+ timeDiff + "\n" ,Operations.directoryPath + "run.log");

        }

        else if (args[5].equals("3DES")){
            TripleDES tripleDES = new TripleDES((args[0].equals("-e"))? plainTextFile[0].getBytes():cipherTextFile,keys[1],keys[0], keys[2]);

            switch(args[6]){

                case "CBC":
                    if(args[0].equals("-e")){
                        startTime = System.currentTimeMillis();
                        encryptedOrDecrypted = tripleDES.CBCEncryption("TripleDES");
                    }else if (args[0].equals("-d")){
                        startTime = System.currentTimeMillis();
                        encryptedOrDecrypted = tripleDES.CBCDecryption("TripleDES");
                    }
                    break;
                case "CFB":
                    if(args[0].equals("-e")){
                        startTime = System.currentTimeMillis();
                        encryptedOrDecrypted = tripleDES.CFBEncryption("TripleDES");
                    }else if (args[0].equals("-d")){
                        startTime = System.currentTimeMillis();
                        encryptedOrDecrypted = tripleDES.CFBDecryption("TripleDES");
                    }
                    break;
                case "OFB":
                    if(args[0].equals("-e")){
                        startTime = System.currentTimeMillis();
                        encryptedOrDecrypted = tripleDES.OFBEncryption("TripleDES");
                    }else if (args[0].equals("-d")){
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
            if(args[0].equals("-e")){
                Operations.writeAsByte(encryptedOrDecrypted, Operations.directoryPath + args[4]);
            }
            else if(args[0].equals("-d")){
                char[] finalData =  new String(encryptedOrDecrypted).toCharArray();
                String finalString = "";
                for(char c: finalData){
                    if(c != '\u0000'){
                        finalString = finalString+c;
                    }
                }
                Operations.writeToFile(finalString, Operations.directoryPath + args[4]);
            }
            Operations.writeToFile(args[2]+ " "+ args[4]+ " "+ ((args[0].equals("-e"))? "enc": "dec")+" "+args[5]+" "+args[6]+ " "+ timeDiff + "\n" ,Operations.directoryPath + "run.log");



        }



    }

}
