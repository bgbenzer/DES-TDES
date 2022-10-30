public class Main {

    public static void main(String[] args) throws Exception {

        String[] keyFile = Operations.readFile(args[8]); // reading keys from file
        String[] plainTextFile = Operations.readFile(args[3]); // reading plaintext from file

        String[] keys = keyFile[0].split("-"); // Splitting keys based on "-"

//        long startTime = System.currentTimeMillis();
//        long finishTime = System.currentTimeMillis();
//        long timeDiff = finishTime-startTime;
//        Operations.writeToFile(args[3]+ " "+ args[5]+ " "+ ((args[1]== "-e")? "enc": "dec")+" "+args[6]+" "+args[7]+ " "+ timeDiff ,"run.log");




        if(args[6].equals("DES")){
            DES des = new DES(plainTextFile[0],keys[1],keys[0], keys[2]);

            System.out.println("====================================");

            byte[] deneme = des.cbcENC();
            System.out.println(deneme.length);


//            System.out.println(ct.length);
//            String pt = ciphers.decrypt(ct,"DES");
//            System.out.println(pt);
        }

        else if (args[6] == "3DES"){
            Ciphers ciphers = new TripleDES(plainTextFile[0],keys[1],keys[0], keys[2]);
        }
    }

}
