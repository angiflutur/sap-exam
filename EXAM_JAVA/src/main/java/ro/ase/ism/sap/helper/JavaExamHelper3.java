package ro.ase.ism.sap.helper;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.spec.*;
import java.util.*;
import java.util.zip.*;
import java.util.Base64;

public class JavaExamHelper3 {

    // === HASH & HMAC ===
    public static String hash(String input, String algorithm) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        return bytesToHex(digest.digest(input.getBytes(StandardCharsets.UTF_8)));
    }

    public static String hmac(String key, String data, String algorithm) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), algorithm);
        Mac mac = Mac.getInstance(algorithm);
        mac.init(secretKey);
        return bytesToHex(mac.doFinal(data.getBytes()));
    }

    // === KEY GENERATION ===
    public static SecretKey deriveKey(String password, byte[] salt, int iterations, int keySize) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keySize);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    // === AES ===
    public static byte[] aesEncrypt(String plainText, SecretKey key, IvParameterSpec iv, boolean useCBC) throws Exception {
        Cipher cipher = Cipher.getInstance(useCBC ? "AES/CBC/PKCS5Padding" : "AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, useCBC ? iv : null);
        return cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
    }

    public static String aesDecrypt(byte[] cipherText, SecretKey key, IvParameterSpec iv, boolean useCBC) throws Exception {
        Cipher cipher = Cipher.getInstance(useCBC ? "AES/CBC/PKCS5Padding" : "AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, useCBC ? iv : null);
        return new String(cipher.doFinal(cipherText), StandardCharsets.UTF_8);
    }

    // === 3DES ===
    public static byte[] tripleDesEncrypt(String text, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(text.getBytes());
    }

    public static String tripleDesDecrypt(byte[] encrypted, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(encrypted));
    }

    // === OTP XOR ===
    public static byte[] otp(byte[] input, byte[] key) {
        byte[] output = new byte[input.length];
        for (int i = 0; i < input.length; i++) {
            output[i] = (byte) (input[i] ^ key[i % key.length]);
        }
        return output;
    }

    // === RSA ===
    public static byte[] rsaDecrypt(String keystorePath, String alias, String password, byte[] data) throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream(keystorePath), password.toCharArray());
        PrivateKey privateKey = (PrivateKey) ks.getKey(alias, password.toCharArray());
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    public static byte[] rsaSign(String keystorePath, String alias, String password, byte[] data) throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream(keystorePath), password.toCharArray());
        PrivateKey privateKey = (PrivateKey) ks.getKey(alias, password.toCharArray());
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    public static boolean rsaVerify(String keystorePath, String alias, byte[] data, byte[] sigBytes) throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream(keystorePath), null);
        Certificate cert = ks.getCertificate(alias);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(cert);
        signature.update(data);
        return signature.verify(sigBytes);
    }

    // === FILE HANDLING ===
    public static void shiftFile(String inputFile, String outputFile, boolean left) throws Exception {
        byte[] content = Files.readAllBytes(Paths.get(inputFile));
        for (int i = 0; i < content.length; i++) {
            content[i] = left ? (byte)((content[i] << 2) | ((content[i] & 0xFF) >>> 6))
                    : (byte)(((content[i] & 0xFF) >>> 2) | (content[i] << 6));
        }
        Files.write(Paths.get(outputFile), content);
    }

    public static void encryptFileAES(String inFile, String outFile, SecretKey key, IvParameterSpec iv, boolean useCBC) throws Exception {
        byte[] content = Files.readAllBytes(Paths.get(inFile));
        Cipher cipher = Cipher.getInstance(useCBC ? "AES/CBC/PKCS5Padding" : "AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, useCBC ? iv : null);
        byte[] encrypted = cipher.doFinal(content);
        Files.write(Paths.get(outFile), encrypted);
    }

    public static void decryptFileAES(String inFile, String outFile, SecretKey key, IvParameterSpec iv, boolean useCBC) throws Exception {
        byte[] content = Files.readAllBytes(Paths.get(inFile));
        Cipher cipher = Cipher.getInstance(useCBC ? "AES/CBC/PKCS5Padding" : "AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, useCBC ? iv : null);
        byte[] decrypted = cipher.doFinal(content);
        Files.write(Paths.get(outFile), decrypted);
    }

    public static void encryptFileOTP(String inFile, String outFile, byte[] key) throws Exception {
        byte[] content = Files.readAllBytes(Paths.get(inFile));
        byte[] encrypted = otp(content, key);
        Files.write(Paths.get(outFile), encrypted);
    }

    public static void decryptFileOTP(String inFile, String outFile, byte[] key) throws Exception {
        encryptFileOTP(inFile, outFile, key); // OTP XOR is symmetric
    }

    // === UTILS ===
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public static byte[] readFile(String filename) throws IOException {
        return Files.readAllBytes(Paths.get(filename));
    }

    public static void writeFile(String filename, byte[] data) throws IOException {
        Files.write(Paths.get(filename), data);
    }

    public static void main(String[] args) throws Exception {
        String msg = "Mesaj secret!";
        byte[] salt = SecureRandom.getInstanceStrong().generateSeed(16);
        SecretKey key = deriveKey("parolaMea", salt, 1000, 128);
        IvParameterSpec iv = new IvParameterSpec(SecureRandom.getInstanceStrong().generateSeed(16));

        byte[] enc = aesEncrypt(msg, key, iv, true);
        System.out.println("AES CBC Encrypted (base64): " + Base64.getEncoder().encodeToString(enc));
        System.out.println("Decrypted: " + aesDecrypt(enc, key, iv, true));
    }
}
