package exam.exam_2023_january;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;

public class Ianuarie2023 {
    // The user taken into account was considered ANONYMOUS from the users.pdf

    final static String filePass = "userfilepass@9]9";
    final static String salt = "ism2021";
    final static String filePath = "src/main/java/exam/exam_2023_january/pbkdf.enc";
    final static String refBase64 = "pP+QN170gTIZzl/AfxFscko/OnJ3Gb9y1274ZTCpu/c=";
    final static String keyStorePath = "src/main/java/exam/exam_2023_january/keystore.jks";
    final static char[] keyStorePass = "password".toCharArray();

    static File Cerinta1() throws Exception {
        File dir = new File("src/main/java/exam/exam_2023_january/users2");
        File[] files = dir.listFiles();
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        Base64.Encoder base64Encoder = Base64.getEncoder();
        byte[] buffer = new byte[8];
        int bytesRead;
        if (files != null) {
            for (File f : files) {
                try (FileInputStream fis = new FileInputStream(f)) {
                    while ((bytesRead = fis.read(buffer)) != -1) {
                        sha256.update(buffer, 0, bytesRead);
                    }
                    if (base64Encoder.encodeToString(sha256.digest()).equals(refBase64)) {
                        System.out.printf("The user file name is: %s%n", f.getName());
                        return f;
                    }
                    sha256.reset();
                }
            }
        }
        return null;
    }

    static String Cerinta2() throws Exception {
        File result = Cerinta1();
        try (FileInputStream fis = new FileInputStream(result)) {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            SecretKeySpec secretKeySpec = new SecretKeySpec(filePass.getBytes(), "AES");
            byte[] iv = new byte[cipher.getBlockSize()];
            iv[10] = (byte) 0xff;
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

            byte[] buffer = new byte[cipher.getBlockSize()];
            int readBytes;
            System.out.print("The password is: ");
            StringBuffer sb = new StringBuffer();
            while ((readBytes = fis.read(buffer)) != -1) {
                String intermediate = new String(cipher.update(buffer, 0, readBytes));
                System.out.print(intermediate);
                sb.append(intermediate);
            }
            String finalString = new String(cipher.doFinal());
            System.out.println(finalString);
            sb.append(finalString);
            return sb.toString();
        }
    }

    static int Cerinta3() throws Exception {
        String password = Cerinta2();
        String saltedPass = password + salt;
        int bytesWritten;
        PBEKeySpec pbeKeySpec = new PBEKeySpec(saltedPass.toCharArray(), password.getBytes(), 150, 160);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            byte[] toWrite = secretKeyFactory.generateSecret(pbeKeySpec).getEncoded();
            fos.write(toWrite);
            bytesWritten = toWrite.length;
        }
        // verification
        PBEKeySpec pbeKeySpec2 = new PBEKeySpec(("root@8#7@9%8@6@3" + salt).toCharArray(), password.getBytes(), 150, 160);
        try (FileInputStream fis = new FileInputStream(filePath)) {
            byte[] buffer = new byte[20];
            int bytesRead = fis.read(buffer);
            if (bytesRead != 20) {
                throw new UnsupportedOperationException("The file is not there.");
            }
            if (Arrays.equals(secretKeyFactory.generateSecret(pbeKeySpec2).getEncoded(), buffer)) {
                System.out.println("The password is correct.");
            } else {
                System.out.println("The password is incorrect.");
            }
        }
        return bytesWritten;
    }

    static void ToateCerintele() throws Exception {
        int writtenBytes = Cerinta3();

        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(keyStorePath)) {
            keyStore.load(fis, keyStorePass);
            PrivateKey pk = (PrivateKey) keyStore.getKey("mykey", keyStorePass);
            try (FileInputStream fis2 = new FileInputStream(filePath)) {
                byte[] buffer = new byte[writtenBytes];
                int bytesRead = fis2.read(buffer);
                if (bytesRead != writtenBytes) {
                    throw new UnsupportedOperationException("The file is not there.");
                }
                Signature signature = Signature.getInstance("SHA256withRSA");
                signature.initSign(pk);
                signature.update(buffer);

                byte[] signatureBytes = signature.sign();

                try (FileOutputStream fos = new FileOutputStream("src/main/java/exam/exam_2023_january/pbkdf.sig")) {
                    fos.write(signatureBytes);
                }
            }
        }

        // verification

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        FileInputStream certFis = new FileInputStream("src/main/java/exam/exam_2023_january/public.cer");
        X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(certFis);
        certFis.close();

        PublicKey publicKey = cert.getPublicKey();

        try (FileInputStream fis1 = new FileInputStream(filePath)) {
            byte[] buffer = new byte[writtenBytes];
            int bytesRead = fis1.read(buffer);
            if (bytesRead != writtenBytes) {
                throw new UnsupportedOperationException("The file is not there.");
            }
            try (FileInputStream fis2 = new FileInputStream("src/main/java/exam/exam_2023_january/pbkdf.sig")) {
                Signature signature = Signature.getInstance("SHA256withRSA");
                signature.initVerify(publicKey);
                signature.update(buffer);
                byte[] sigBytes = fis2.readAllBytes();
                boolean isValid = signature.verify(sigBytes);
                if (isValid) {
                    System.out.println("The signature is valid.");
                } else {
                    System.out.println("The signature is invalid.");
                }
            }
        }
    }

    public static void main(String[] args) throws Exception {
        ToateCerintele();
    }
}
