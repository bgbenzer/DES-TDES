import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Operations {
    public static String directoryPath = "";

    public static String[] readFile(String path) {
        directoryPath = "";
        String[] arrOfStr = path.split("\\\\");
        for(int i = 0; i < arrOfStr.length - 1; i++) {
            directoryPath += arrOfStr[i] + "\\";
        }

        try {
            int i = 0;
            int length = Files.readAllLines(Paths.get(path)).size();
            String[] results = new String[length];								//Reading files.
            for (String line : Files.readAllLines(Paths.get(path))) {
                results[i++] = line;
            }
            return results;
        }
        catch (IOException e) {
            e.printStackTrace();
            return null;
        }

    }

    public static void writeToFile(String str1, String outputFile){

        File file = new File(outputFile);

        try{

            file.createNewFile();
            FileWriter writer = new FileWriter(outputFile,true);

            writer.write(str1);

            writer.close();
        }
        catch(IOException e){
            System.out.println("error");
        }

    }

    public static byte[] readAsByte(String fileName) throws IOException {
        directoryPath = "";
        String[] arrOfStr = fileName.split("\\\\");
        for(int i = 0; i < arrOfStr.length - 1; i++) {
            directoryPath += arrOfStr[i] + "\\";
        }

        byte[] bytes = Files.readAllBytes(Paths.get(fileName));
        return bytes;
    }

    public static void writeAsByte(byte[] data, String outputFileName) throws IOException { //TODO
        Files.write(Paths.get(outputFileName),data);
    }
}
