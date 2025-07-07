package assignments;

import java.io.*;
import java.security.*;

public class Assignment02 {

    // MD5
    public static byte[] hashMD5(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(input.getBytes());
    }

    // SHA256
    public static byte[] hashSHA256(byte[] input) throws NoSuchAlgorithmException {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        return sha.digest(input);
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        String myHash = "37148ecff62445f8817d184d6412c00aa0263de88286ba94ebea5a3d692bdfa5";

        long tstart = System.currentTimeMillis();

        FileReader fileReader = new FileReader("src/main/java/assignments/FluturAngelicaCostela/ignis-10M.txt");
        BufferedReader bufferReader = new BufferedReader(fileReader);

        String prefix = "ismsap";

        while (true) {
            String password = bufferReader.readLine();
            String prefixedPassword = prefix + password;

            byte[] md5Hash = hashMD5(prefixedPassword);
            byte[] finalHash = hashSHA256(md5Hash);

            StringBuilder hexString = new StringBuilder();
            for (byte b : finalHash) {
                hexString.append(String.format("%02x", b));
            }

            if (hexString.toString().equals(myHash)) {
                long tfinal = System.currentTimeMillis();
                System.out.println("Password found: " + password);
                System.out.println("Duration is: " + (tfinal - tstart) + " milliseconds");
                break;
            }
        }
    }
}
