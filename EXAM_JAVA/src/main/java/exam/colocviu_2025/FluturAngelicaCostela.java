package exam.colocviu_2025;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

//rename the class with your name
//use a package with the next pattern 
//	ro.ase.ism.sap.lastname.firstname
public class FluturAngelicaCostela {

    public static String getHex(byte[] values) {
        StringBuffer sb = new StringBuffer();
        for (byte b : values) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    // 1. Step 1: return your file name
    public static String findFile(String hash) throws NoSuchAlgorithmException, IOException {
        // CERINTA 1

        File directory = new File("safecorp_random_messages");

        File[] files = directory.listFiles();

        for (File file : files) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            FileInputStream fis = new FileInputStream(file);
            BufferedInputStream bis = new BufferedInputStream(fis);

            byte[] buffer = new byte[8];
            while (true) {
                int noBytes = bis.read(buffer);
                if (noBytes == -1) {
                    break;
                }
                md.update(buffer, 0, noBytes);
            }
            fis.close();

            byte[] hashBytes = md.digest();
            String fileHash = getHex(hashBytes);

            if (fileHash.equals(hash)) {
                System.out.println(file.getName());
                return file.getName();
            }
        }
        return "File not found.";
    }

    ;

    // 2. Step 2: Generate HMAC for Authentication
    public static void generateHMAC(String filename, String sharedSecret) throws NoSuchAlgorithmException, InvalidKeyException, IOException {
        // CERINTA 2

        Mac hmac = Mac.getInstance("HmacSha256");
        SecretKeySpec key = new SecretKeySpec(sharedSecret.getBytes(), "HmacSha256");
        hmac.init(key);

        //read the file and process it
        File inputFile = new File("safecorp_random_messages/" + filename);
        if (!inputFile.exists()) {
            throw new UnsupportedOperationException("File is missing");
        }
        FileInputStream fis = new FileInputStream(inputFile);
        BufferedInputStream bis = new BufferedInputStream(fis);
        FileOutputStream fos = new FileOutputStream("src/main/java/exam/colocviu_2025/flutur_hmac.txt");

        byte[] buffer = new byte[8];
        while (true) {
            int noBytes = bis.read(buffer);
            if (noBytes == -1) {
                break;
            }
            hmac.update(buffer, 0, noBytes);
        }

        fis.close();

        byte[] result = hmac.doFinal();
        String hexResult = getHex(result);
        fos.write(hexResult.getBytes());
    }

    // 3. Step 3: Derive Key with PBKDF2
    public static byte[] deriveKeyWithPBKDF2(
            String password, int noIterations, int keySize) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        // CERINTA 3
        FileInputStream saltFile = new FileInputStream("src/main/java/exam/colocviu_2025/flutur_salt.txt");
        byte[] saltBytes = saltFile.readAllBytes();
        String salt = new String(saltBytes).trim();

        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(),
                salt.getBytes(),
                noIterations,
                keySize);
        SecretKeyFactory pbkdf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

        SecretKey key = pbkdf.generateSecret(pbeKeySpec);
        return key.getEncoded();
    }

    // 4. Step 4: Encrypt File with AES and Save IV
    public static void encryptFileWithAES(String filename, byte[] key) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        FileInputStream fis = new FileInputStream("safecorp_random_messages/" + filename);
        FileOutputStream fos = new FileOutputStream("src/main/java/exam/colocviu_2025/flutur_encrypted.txt");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        byte[] IV = new byte[cipher.getBlockSize()];
        IV[3] = (byte) 0b00000010;
        FileOutputStream ivFile = new FileOutputStream("src/main/java/exam/colocviu_2025/flutur_iv.txt");
        ivFile.write(getHex(IV).getBytes());

        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        byte[] buffer = new byte[cipher.getBlockSize()];
        while (true) {
            int noBytes = fis.read(buffer);
            if (noBytes == -1) {
                break;
            }
            byte[] output = cipher.update(buffer, 0, noBytes);
            fos.write(getHex(output).getBytes());
        }
        byte[] output = cipher.doFinal();
        fos.write(getHex(output).getBytes());
        fis.close();
        fos.close();
    }

    // 5. Step 5: Encrypt with 3DES for Archival
    public static void encryptWith3DES(String filename, byte[] key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "DESede");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        try(var fis = new FileInputStream("safecorp_random_messages/"+filename)) {
            byte[] content = fis.readAllBytes();
            try(var fos = new FileOutputStream("src/main/java/exam/colocviu_2025/archived.sec"))
            {
                fos.write(cipher.doFinal(content));
            }
        }
    }

    // 6. Step 6: Apply Cyclic Bitwise Shift
    public static void applyCyclicShift(String filename) throws IOException {
        try(var fis = new FileInputStream(filename))
        {
            var allBytes = fis.readAllBytes();
            System.out.println();
            try(var fos = new FileOutputStream("src/main/java/exam/colocviu_2025/flutur_obfuscated.txt")) {

                for (var b : allBytes) {
                    String binaryRep = Integer.toBinaryString(b);
                    String fullBinaryRep = String.format("%1$" + 8 + "s", binaryRep).replace(' ', '0');
                    System.out.printf("Initial bit rep: %s ---- %s hex rep%n", fullBinaryRep, Integer.toHexString(b));
                    StringBuffer sb = new StringBuffer();
                    for (int i = 2; i < fullBinaryRep.length(); i++) {
                        sb.append(fullBinaryRep.charAt(i));
                    }
                    sb.append(fullBinaryRep.charAt(0));
                    sb.append(fullBinaryRep.charAt(1));
                    String shiftedByteRep = sb.toString();
                    int parsedInt = Integer.parseInt(shiftedByteRep, 2);
                    System.out.printf("Rotated bit rep: %s ---- %02x hex rep%n%n", shiftedByteRep, parsedInt);
                    fos.write(parsedInt);
                }
            }
        }
    }

    public static void main(String[] args) {

        String hash = "3D83EE9BF413FEC9F5B16A3A254ACC0E0A9893E1037F5F2309521231A6E796C3"; //copy it from the given Excel file
        String sharedSecret = "cog(m3^E$`Mc"; //copy it from the given Excel file
        int noIterations = 61676; //copy it from the given Excel file

        try {
            // 1. Step 1
            String filename = findFile(hash);

            // 2. Step 2: Generate HMAC for Authentication
            generateHMAC(filename, sharedSecret);

            int keySize = 132;
            byte[] key;
            // 3. Step 3: Derive Key with PBKDF2
            key = deriveKeyWithPBKDF2(sharedSecret, noIterations, keySize);

            // 4. Step 4: Encrypt File with AES and Save IV
            encryptFileWithAES(filename, key);

            // 5. Step 5: Encrypt with 3DES for Archival
            keySize = 192;
            key = deriveKeyWithPBKDF2(sharedSecret, noIterations, keySize);
            encryptWith3DES(filename, key);

            // 6. Step 6: Apply Cyclic Bitwise Shift
            applyCyclicShift("src/main/java/exam/colocviu_2025/flutur_encrypted.txt");

        } catch (Exception e) {
            System.out.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
        }
    }

}
