package exam.exam_2024_july;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class Exam {

    public static File Cerinta1() throws Exception {
        File dir = new File("src/main/java/exam/exam_2024_july/system32");
        File[] files = dir.listFiles();

        // Citim hash-urile corecte din fisierul sha2Fingerprints.txt
        Map<String, String> hashToFileName = new HashMap<>();
        BufferedReader reader = new BufferedReader(new FileReader("src/main/java/exam/exam_2024_july/sha2Fingerprints.txt"));
        String fileName;
        while ((fileName = reader.readLine()) != null) {
            String hash = reader.readLine();
            hashToFileName.put(hash, fileName);
        }
        reader.close();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        Base64.Encoder encoder = Base64.getEncoder();

        // Verificam fiecare fisier din system32
        for (File file : files) {
            FileInputStream fis = new FileInputStream(file);
            byte[] fileBytes = fis.readAllBytes();
            fis.close();

            // Calculam SHA256 si il convertim in Base64
            byte[] hashBytes = digest.digest(fileBytes);
            String fileHashBase64 = encoder.encodeToString(hashBytes);

            // Daca hash-ul nu apare in lista celor corecte => fisierul a fost modificat
            if (!hashToFileName.containsKey(fileHashBase64)) {
                System.out.println("Fișierul modificat este: " + file.getName());
                return file;
            }
        }

        System.out.println("Toate fișierele sunt originale.");
        return null;
    }


    static void Cerinta2() throws Exception {
        File result = Cerinta1();
        FileInputStream fis = new FileInputStream(result);
        byte[] pass = fis.readAllBytes();
        fis.close();

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(pass, "AES");

        byte[] iv = new byte[cipher.getBlockSize()];
        int length = iv.length;
        iv[length - 1] = (byte) 0x17; // 23
        iv[length - 2] = (byte) 0x14; // 20
        iv[length - 3] = (byte) 0x02;
        iv[length - 4] = (byte) 0x03;
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        FileInputStream fis2 = new FileInputStream("src/main/java/exam/exam_2024_july/financialdata.enc");
        FileWriter fw = new FileWriter("src/main/java/exam/exam_2024_july/financialdata.txt");
        BufferedWriter bw = new BufferedWriter(fw);

        byte[] buffer = new byte[1024];
        int readBytes;

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        while ((readBytes = fis2.read(buffer)) != -1) {
            baos.write(buffer, 0, readBytes);
        }
        fis2.close();

        byte[] decrypted = cipher.doFinal(baos.toByteArray());
        String decryptedText = new String(decrypted);
        bw.write(decryptedText);
        bw.close();
    }

    static void Cerinta3() throws Exception {
        Cerinta2();

        // Citim primul IBAN
        BufferedReader br = new BufferedReader(new FileReader("src/main/java/exam/exam_2024_july/financialdata.txt"));
        String IBAN = br.readLine();
        br.close();

        FileWriter fw = new FileWriter("src/main/java/exam/exam_2024_july/myresponse.txt");
        fw.write(IBAN);
        fw.close();

        FileInputStream fis = new FileInputStream("src/main/java/exam/exam_2024_july/myresponse.txt");

        // Inițializăm keystore
        KeyStore keyStore = KeyStore.getInstance("JKS");
        FileInputStream kss = new FileInputStream("src/main/java/exam/exam_2024_july/mykeystore.jks");
        keyStore.load(kss, "password".toCharArray());
        kss.close();

        PrivateKey privateKey = (PrivateKey) keyStore.getKey("mykey", "password".toCharArray());

        byte[] fileData = fis.readAllBytes();
        fis.close();

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(fileData);
        byte[] digitalSignature = signature.sign();

        FileOutputStream fos = new FileOutputStream("src/main/java/exam/exam_2024_july/DataSignature.ds");
        fos.write(digitalSignature);
        fos.close();
    }

    public static void main(String[] args) throws Exception {
        Cerinta3();
    }
}
