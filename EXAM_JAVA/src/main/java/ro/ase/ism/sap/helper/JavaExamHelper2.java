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

public class JavaExamHelper2 {

    // SHA-256 Hash
    public static String sha256(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return bytesToHex(digest.digest(input.getBytes(StandardCharsets.UTF_8)));
    }

    // SHA-1 Hash
    public static String sha1(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        return bytesToHex(digest.digest(input.getBytes(StandardCharsets.UTF_8)));
    }

    // MD5 Hash
    public static String md5(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        return bytesToHex(digest.digest(input.getBytes(StandardCharsets.UTF_8)));
    }

    // HMAC with SHA256
    public static String hmacSha256(String key, String data) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKey);
        return bytesToHex(mac.doFinal(data.getBytes()));
    }

    // HMAC with SHA1
    public static String hmacSha1(String key, String data) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(secretKey);
        return Base64.getEncoder().encodeToString(mac.doFinal(data.getBytes()));
    }

    // PBKDF2 Key Derivation
    public static SecretKey deriveKeyPBKDF2(String password, byte[] salt, int iterations, int keySize) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keySize);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    // AES Encryption CBC
    public static byte[] aesEncryptCBC(String plainText, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
    }

    // AES Decryption CBC
    public static String aesDecryptCBC(byte[] cipherText, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return new String(cipher.doFinal(cipherText), StandardCharsets.UTF_8);
    }

    // AES Encryption ECB
    public static byte[] aesEncryptECB(String plainText, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
    }

    // AES Decryption ECB
    public static String aesDecryptECB(byte[] cipherText, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(cipherText), StandardCharsets.UTF_8);
    }

    // 3DES ECB
    public static byte[] tripleDesEncryptECB(String text, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(text.getBytes());
    }

    // RSA Decryption from Keystore
    public static byte[] rsaDecryptFromKeystore(String keystorePath, String alias, String password, byte[] data) throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream(keystorePath), password.toCharArray());
        PrivateKey privateKey = (PrivateKey) ks.getKey(alias, password.toCharArray());

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    // Sign File using RSA
    public static byte[] signFileRSA(String keystorePath, String alias, String password, byte[] fileBytes) throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream(keystorePath), password.toCharArray());
        PrivateKey privateKey = (PrivateKey) ks.getKey(alias, password.toCharArray());

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(fileBytes);
        return signature.sign();
    }

    // OTP XOR Encrypt/Decrypt
    public static byte[] otp(byte[] input, byte[] key) {
        byte[] output = new byte[input.length];
        for (int i = 0; i < input.length; i++) {
            output[i] = (byte) (input[i] ^ key[i % key.length]);
        }
        return output;
    }

    // Bitwise left circular shift on byte
    public static byte circularLeftShift(byte b, int shift) {
        return (byte) ((b << shift) | ((b & 0xFF) >>> (8 - shift)));
    }

    // Bitwise right circular shift on byte
    public static byte circularRightShift(byte b, int shift) {
        return (byte) (((b & 0xFF) >>> shift) | (b << (8 - shift)));
    }

    // Apply circular shift to file
    public static void shiftFile(String inputFile, String outputFile, boolean left) throws Exception {
        byte[] content = Files.readAllBytes(Paths.get(inputFile));
        for (int i = 0; i < content.length; i++) {
            content[i] = left ? circularLeftShift(content[i], 2) : circularRightShift(content[i], 2);
        }
        Files.write(Paths.get(outputFile), content);
    }

    // Utility Methods
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public static void saveBytesToFile(String filename, byte[] data) throws IOException {
        Files.write(Paths.get(filename), data);
    }

    public static byte[] readBytesFromFile(String filename) throws IOException {
        return Files.readAllBytes(Paths.get(filename));
    }

    public static void saveBase64ToFile(String filename, byte[] data) throws IOException {
        String base64 = Base64.getEncoder().encodeToString(data);
        Files.write(Paths.get(filename), base64.getBytes());
    }

    public static byte[] readBase64FromFile(String filename) throws IOException {
        String base64 = Files.readString(Paths.get(filename));
        return Base64.getDecoder().decode(base64);
    }

    public static void main(String[] args) throws Exception {
        // Exemplu de folosire:
        String message = "Hello, exam!";
        System.out.println("SHA-256: " + sha256(message));
        System.out.println("MD5: " + md5(message));
        System.out.println("HMAC-SHA256: " + hmacSha256("secret", message));

        byte[] salt = SecureRandom.getInstanceStrong().generateSeed(16);
        SecretKey key = deriveKeyPBKDF2("password123", salt, 150, 128);
        IvParameterSpec iv = new IvParameterSpec(SecureRandom.getInstanceStrong().generateSeed(16));

        byte[] enc = aesEncryptCBC(message, key, iv);
        System.out.println("Encrypted AES-CBC (base64): " + Base64.getEncoder().encodeToString(enc));
        System.out.println("Decrypted: " + aesDecryptCBC(enc, key, iv));
    }
}
