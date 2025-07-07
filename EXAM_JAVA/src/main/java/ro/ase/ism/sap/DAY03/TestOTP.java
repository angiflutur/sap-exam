package ro.ase.ism.sap.DAY03;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class TestOTP {
    public static byte[] generateRandomKey(int keySizeInBytes) throws NoSuchAlgorithmException {
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        byte[] random = new byte[keySizeInBytes];
        secureRandom.nextBytes(random);
        return random;
    }

    public static byte[] otpEncryptDecrypt(byte[] plainText, byte[] key){
        if(plainText.length != key.length){
            throw new UnsupportedOperationException("Must have same length");
        }

        byte[] cipher = new byte[plainText.length];

        for(int i = 0; i < plainText.length; i++){
            cipher[i] = (byte)(plainText[i] ^ key[i]);
        }
        return cipher;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        String msg = "The requirements for tomorrow are...";
        byte[] randomKey = generateRandomKey(msg.length());
        System.out.println("Random Key: " + Utility.getHex(randomKey));

        byte[] encMsg = otpEncryptDecrypt(msg.getBytes(), randomKey);

        //DON'T
        //String randomKeyString = new String[randomKey];

        String randomKeyString = Base64.getEncoder().encodeToString(randomKey);
        System.out.println("Random Key: " + randomKeyString);
        System.out.println("Encrypted Message: " + Utility.getHex(encMsg));

        //decryption
        byte[] initialMessage = otpEncryptDecrypt(encMsg, randomKey);
        String initialMessageString = new String(initialMessage);
        System.out.println("Initial Message: " + initialMessageString);
    }
}
