import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Operations {

    public static String[] readFile(String path) {
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

    public static void writeToFile(String str1){

        File file = new File("output.txt");

        try{

            file.createNewFile();
            FileWriter writer = new FileWriter("output.txt",true);

            writer.write(str1);
            writer.write("\n");

            writer.close();
        }
        catch(IOException e){
            System.out.println("error");
        }

    }


}
