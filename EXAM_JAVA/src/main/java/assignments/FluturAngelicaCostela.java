package assignments;

import javax.crypto.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class FluturAngelicaCostela {

    public static PublicKey getPublicFromX509(String filename) throws FileNotFoundException, CertificateException {
        File file = new File(filename);
        if (!file.exists()) {
            throw new UnsupportedOperationException("Missing file.");
        }
        FileInputStream fis = new FileInputStream(file);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) factory.generateCertificate(fis);
        return cert.getPublicKey();
    }

    public static boolean isValid(String filename, byte[] signature, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException {
        File inputFile = new File(filename);
        if (!inputFile.exists()) {
            throw new UnsupportedOperationException("No FILE");
        }
        FileInputStream fis = new FileInputStream(inputFile);
        Signature sign = Signature.getInstance("SHA512withRSA");
        sign.initVerify(publicKey);
        byte[] buffer = fis.readAllBytes();
        fis.close();
        sign.update(buffer);
        return sign.verify(signature);
    }

    public static SecretKey generateAESKey(int noBits, String algorithm) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
        keyGenerator.init(noBits);
        return keyGenerator.generateKey();
    }

    public static byte[] encryptMessage(Key key, byte[] input) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(input);
    }

    public static byte[] encryptKey(PublicKey key, byte[] input) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(input);
    }

    public static byte[] getDigitalSignature(String file, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException {
        File inputFile = new File(file);
        if (!inputFile.exists()) {
            throw new UnsupportedOperationException("No FILE: " + file);
        }
        FileInputStream fis = new FileInputStream(inputFile);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        byte[] buffer = fis.readAllBytes();
        signature.update(buffer);
        fis.close();
        return signature.sign();
    }

    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        return keyPairGen.generateKeyPair();
    }

    static void generateCertificate() throws Exception {
        String keyPairName = "flutur_angelica_costela_keypair";
        String keyStoreName = "flutur_angelica_costela_keystore.jks";
        String storePass = "store_password";
        String keyPass = "key_password";

        String[] command = {
                "keytool",
                "-genkeypair",
                "-alias", keyPairName,
                "-keyalg", "RSA",
                "-keysize", "2048",
                "-validity", "365",
                "-storetype", "JKS",
                "-keystore", keyStoreName,
                "-dname", "CN=Flutur Angelica Costela",
                "-storepass", storePass,
                "-keypass", keyPass
        };

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);

        Process process = pb.start();

        int exitCode = process.waitFor();
        if (exitCode != 0) {
            System.out.println("Error generating the certificate.");
        }
    }

    public static void main(String[] args) throws Exception {
        generateCertificate();

        PublicKey professorPublicKey = getPublicFromX509("SimplePGP_ISM.cer");

        String validFile = null;
        for (int i = 1; i <= 3; i++) {
            String currentFile = "SAPExamSubject" + i;
            File signatureFile = new File(currentFile + ".signature");
            byte[] signatureBytes = new byte[(int) signatureFile.length()];
            try (FileInputStream fis = new FileInputStream(signatureFile)) {
                fis.read(signatureBytes);
            }
            if (isValid(currentFile + ".txt", signatureBytes, professorPublicKey)) {
                validFile = currentFile + ".txt";
                System.out.println("Valid file: " + validFile);
                break;
            }
        }

        String responseMessage = "Hello, professor!\n" +
                "My name is Flutur Angelica-Costela.\n" +
                "Are we allowed to use our personal notes during the exam?\n" +
                "Thank you!";

        FileOutputStream fos = new FileOutputStream("response.txt");
        fos.write(responseMessage.getBytes());

        SecretKey aesKey = generateAESKey(128, "AES");

        byte[] encryptedResponse = encryptMessage(aesKey, responseMessage.getBytes());

        FileOutputStream responseFile = new FileOutputStream("response.sec");
        responseFile.write(encryptedResponse);
        responseFile.close();

        byte[] encryptedAESKey = encryptKey(professorPublicKey, aesKey.getEncoded());
        FileOutputStream aesKeyFile = new FileOutputStream("aes_key.sec");
        aesKeyFile.write(encryptedAESKey);
        aesKeyFile.close();

        KeyPair keyPair = generateRSAKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();

        byte[] signature = getDigitalSignature("response.sec", privateKey);
        FileOutputStream signatureFile = new FileOutputStream("signature.ds");
        signatureFile.write(signature);
        signatureFile.close();
    }
}
