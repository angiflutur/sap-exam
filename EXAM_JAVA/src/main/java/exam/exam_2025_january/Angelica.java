package exam.exam_2025_january;


import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

public class Angelica {

    // Use this static variables to hardcode algorithm names and other important values
    private static final String HASH_ALGORITHM = "MD5";
    private static final String HMAC_ALGORITHM = "HmacSha1";
    private static final String SHARED_SECRET = "30^X9|Y.x\"v81234\n"; // Secret key for HMAC authentication from the Excel file
    private static final String AES_ALGORITHM = "AES/ECB/PKCS5Padding";
    private static final String FOLDER_PATH = "messages";
    private static final String DIGEST_FOLDER = "messages_digest";
    private static final String HMAC_FOLDER = "messages_hmac";

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02X", b));
        return sb.toString();
    }

    // Step 1: Generate Digest values of all the files from the given folder
    public static void generateFilesDigest(String folderPath) throws Exception {
        File folder = new File(folderPath);
        if (!folder.exists()) {
            throw new Exception(folderPath + " does not exist");
        }
        new File(DIGEST_FOLDER).mkdirs(); // ensure digest folder exists
        for (File file : folder.listFiles()) {
            if (file.isFile() && file.getName().endsWith(".txt")) {
                MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);
                byte[] content = Files.readAllBytes(file.toPath());
                byte[] digest = md.digest(content);

                String digestHex = bytesToHex(digest);
                String outputFile = DIGEST_FOLDER + "/" + file.getName().replace(".txt", ".digest");
                try (BufferedWriter bw = new BufferedWriter(new FileWriter(outputFile))) {
                    bw.write(digestHex);
                }
            }
        }
    }

    // Step 2: Generate HMAC-SHA256 authentication code
    public static void generateFilesHMAC(String folderPath, String secretKey) throws Exception {
        File folder = new File(folderPath);
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(), HMAC_ALGORITHM);
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(keySpec);

        new File(HMAC_FOLDER).mkdirs(); // ensure hmac folder exists
        for (File file : folder.listFiles()) {
            if (file.isFile() && file.getName().endsWith(".txt")) {
                byte[] content = Files.readAllBytes(file.toPath());
                byte[] hmac = mac.doFinal(content);
                String hmacBase64 = Base64.getEncoder().encodeToString(hmac);
                String outputFile = HMAC_FOLDER + "/" + file.getName().replace(".txt", ".hmac");
                try (BufferedWriter bw = new BufferedWriter(new FileWriter(outputFile))) {
                    bw.write(hmacBase64);
                }
            }
        }
    }


    // Step 3: Decrypt and verify the document
    public static boolean retrieveAndVerifyDocument(String file, String hashFile, String hmacFile, String secretKey) throws Exception {
        // Verify HMAC and digest for the given file
        // Return true if the files has not been changed
        byte[] content = Files.readAllBytes(new File(file).toPath());

        //compute current digest
        MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);
        byte[] computedDigest = md.digest(content);
        String computedDigestHex = bytesToHex(computedDigest);

        //read saved digest
        String savedDigest = Files.readString(new File(hashFile).toPath()).trim();

        //compute HMAC
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(), HASH_ALGORITHM);
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(keySpec);
        byte[] computedHMAC = mac.doFinal(content);
        String computedHMACBase64 = Base64.getEncoder().encodeToString(computedHMAC);

        // read saved HMAC
        String savedHMAC = Files.readString(new File(hmacFile).toPath()).trim();

        boolean digestMatch = savedDigest.equals(computedDigestHex);
        boolean hmacMatch = savedHMAC.equals(computedHMACBase64);

        if (digestMatch && hmacMatch) {
            return true;
        }
        return false;
    }

    // Step 4: Generate AES key from the shared secret. See Excel for details
    public static byte[] generateSecretKey(String sharedSecret) throws Exception {
        //16. Flip the bit 4 of byte 7 from left to right
        byte[] bytes = sharedSecret.getBytes();
        byte[] key = Arrays.copyOf(bytes, 16);

        byte mask = 0x10; // 0001.0000 - bitul 4 de la stanga
        key[6] = (byte)(key[6] ^ mask); //xor-flip 1-0 0-1
        return key;
    }


    // Step 5: Encrypt document with AES and received key
    public static void encryptDocument(String filePath, byte[] key) throws Exception {
        byte[] content = Files.readAllBytes(new File(filePath).toPath());
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encrypted = cipher.doFinal(content);
        String encryptedFile = filePath.replace(".txt", ".enc");
        try(FileOutputStream fos = new FileOutputStream(encryptedFile)) {
            fos.write(encrypted);
        }
    }


    public static void main(String[] args) {


        try {
            // Step 1: Generate and store file digest
            generateFilesDigest(FOLDER_PATH);

            // Step 2: Generate and store HMAC for file authentication
            generateFilesHMAC(FOLDER_PATH, SHARED_SECRET);

            String filename = "messages/message_10_5emaqc.txt"; //choose any message.txt file from the folder and test it
            String hashFile = "messages_digest/message_10_5emaqc.digest"; //the corresponding hash file
            String hmacFile = "messages_hmac/message_10_5emaqc.hmac"; //the corresponding hmac file

            // Step 3: Verify the document
            if (retrieveAndVerifyDocument(filename, hashFile, hmacFile, SHARED_SECRET)) {
                System.out.println("Document retrieved successfully. Integrity verified.");
            } else {
                System.out.println("Document verification failed!");
            }

            //Step 3: Change the file content and re-check it to be sure your solution is correct


            // Step 4: Get the derived key
            byte[] derivedKey = generateSecretKey(SHARED_SECRET);

            // Step 5: Encrypt the document
            encryptDocument(filename, derivedKey);


        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

