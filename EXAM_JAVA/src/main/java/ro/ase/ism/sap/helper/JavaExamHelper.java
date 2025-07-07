package ro.ase.ism.sap.helper;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.*;
import java.util.*;

public class JavaExamHelper {

    // ========================= UTILITY =========================

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02X", b));
        return sb.toString();
    }

    public static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        return data;
    }

    public static void saveToFile(String filename, byte[] data) throws IOException {
        Files.write(Paths.get(filename), data);
    }

    public static byte[] readFile(String filename) throws IOException {
        return Files.readAllBytes(Paths.get(filename));
    }

    // ========================= HASHING =========================

    public static byte[] hashSHA256(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data);
    }

    public static byte[] hashMD5(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data);
    }

    // ========================= HMAC =========================

    public static byte[] computeHMAC(byte[] data, byte[] keyBytes) throws Exception {
        SecretKeySpec key = new SecretKeySpec(keyBytes, "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        return mac.doFinal(data);
    }

    // ========================= PBKDF2 =========================

    public static byte[] deriveKeyPBKDF2(String password, byte[] salt, int iterations, int keyLength) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return skf.generateSecret(spec).getEncoded();
    }

    // ========================= AES/DES CRYPT =========================

    public static byte[] encryptAES(byte[] data, byte[] keyBytes, byte[] iv, String mode, boolean withPadding) throws Exception {
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/" + mode + "/" + (withPadding ? "PKCS5Padding" : "NoPadding"));
        if (!mode.equals("ECB")) cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        else cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static byte[] decryptAES(byte[] cipherText, byte[] keyBytes, byte[] iv, String mode, boolean withPadding) throws Exception {
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/" + mode + "/" + (withPadding ? "PKCS5Padding" : "NoPadding"));
        if (!mode.equals("ECB")) cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        else cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(cipherText);
    }

    public static byte[] encryptDES(byte[] data, byte[] keyBytes, String mode, boolean withPadding) throws Exception {
        SecretKeySpec key = new SecretKeySpec(keyBytes, "DES");
        Cipher cipher = Cipher.getInstance("DES/" + mode + "/" + (withPadding ? "PKCS5Padding" : "NoPadding"));
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    // ========================= OTP (One Time Pad) =========================

    public static byte[] xorBytes(byte[] msg, byte[] key) {
        byte[] result = new byte[msg.length];
        for (int i = 0; i < msg.length; i++) result[i] = (byte) (msg[i] ^ key[i]);
        return result;
    }

    // ========================= RSA =========================

    public static byte[] encryptRSA(byte[] data, PublicKey pubKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        return cipher.doFinal(data);
    }

    public static byte[] decryptRSA(byte[] cipherText, PrivateKey privKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privKey);
        return cipher.doFinal(cipherText);
    }

    // ========================= DIGITAL SIGNATURE =========================

    public static byte[] signData(byte[] data, PrivateKey privateKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(data);
        return sig.sign();
    }

    public static boolean verifySignature(byte[] data, byte[] signature, PublicKey publicKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }

    // ========================= KEYSTORE =========================

    public static KeyStore loadKeyStore(String path, String password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(path)) {
            ks.load(fis, password.toCharArray());
        }
        return ks;
    }

    public static PrivateKey getPrivateKeyFromKeyStore(KeyStore ks, String alias, String password) throws Exception {
        return (PrivateKey) ks.getKey(alias, password.toCharArray());
    }

    public static Certificate getCertificateFromKeyStore(KeyStore ks, String alias) throws Exception {
        return ks.getCertificate(alias);
    }

    // ========================= MAIN TEST =========================

    public static void main(String[] args) throws Exception {
        String message = "Hello, Crypto World!";
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

        // SHA
        System.out.println("SHA-256: " + bytesToHex(hashSHA256(messageBytes)));

        // HMAC
        byte[] hmacKey = "secretkey1234567".getBytes();
        System.out.println("HMAC: " + bytesToHex(computeHMAC(messageBytes, hmacKey)));

        // PBKDF2
        byte[] salt = "12345678".getBytes();
        byte[] derivedKey = deriveKeyPBKDF2("password", salt, 10000, 128);
        System.out.println("PBKDF2 Key: " + bytesToHex(derivedKey));

        // AES CBC
        byte[] iv = new byte[16]; new SecureRandom().nextBytes(iv);
        byte[] encrypted = encryptAES(messageBytes, derivedKey, iv, "CBC", true);
        byte[] decrypted = decryptAES(encrypted, derivedKey, iv, "CBC", true);
        System.out.println("AES Decrypted: " + new String(decrypted));

        // OTP
        byte[] otpKey = new byte[messageBytes.length]; new SecureRandom().nextBytes(otpKey);
        byte[] otpEncrypted = xorBytes(messageBytes, otpKey);
        byte[] otpDecrypted = xorBytes(otpEncrypted, otpKey);
        System.out.println("OTP Decrypted: " + new String(otpDecrypted));
    }
}

