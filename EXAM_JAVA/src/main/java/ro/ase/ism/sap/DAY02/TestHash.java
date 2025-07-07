package ro.ase.ism.sap.DAY02;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;

public class TestHash {

	public static void printHex(byte[] values) {
		System.out.println("HEX: ");
		for (byte b : values) {
			System.out.printf(" %02x", b);
		}
		System.out.println(); // pentru o linie nouă după HEX
	}

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		// Verifică și folosește diferite provideri - Bouncy Castle
		String bouncyCastleProvider = "BC";

		// Verifică dacă providerul este disponibil
		Provider provider = Security.getProvider(bouncyCastleProvider);
		if (provider == null) {
			System.out.println("Bouncy Castle is not available");
		} else {
			System.out.println("Bouncy Castle is available");
		}

		// Încarcă providerul Bouncy Castle
		Security.addProvider(new BouncyCastleProvider());

		// Verifică din nou dacă providerul este disponibil
		provider = Security.getProvider(bouncyCastleProvider);
		if (provider == null) {
			System.out.println("Bouncy Castle is not available");
		} else {
			System.out.println("Bouncy Castle is available");
		}

		// Verifică dacă providerul SUN este disponibil
		provider = Security.getProvider("SUN");
		if (provider == null) {
			System.out.println("SUN is not available");
		} else {
			System.out.println("SUN is available");
		}

		String message = "ISM";

		// Hashing a string
		MessageDigest md = MessageDigest.getInstance("SHA-1", bouncyCastleProvider);
		byte[] hashValue = md.digest(message.getBytes());

		printHex(hashValue);

		md = MessageDigest.getInstance("SHA-1");
		hashValue = md.digest(message.getBytes());

		printHex(hashValue);

		// Hashing a file
		File file = new File("src/main/java/ro/ase/ism/sap/DAY02/Message.txt");
		if (!file.exists()) {
			System.out.println("************* The file is not there");
		}
		FileInputStream fis = new FileInputStream(file);
		BufferedInputStream bis = new BufferedInputStream(fis);

		md = MessageDigest.getInstance("MD5", bouncyCastleProvider);
		byte[] buffer = new byte[8];

		do {
			int noBytes = bis.read(buffer);
			if (noBytes != -1) {
				md.update(buffer, 0, noBytes);
			} else {
				break;
			}
		} while (true);

		// Obține hash-ul final
		hashValue = md.digest();
		bis.close();

		printHex(hashValue);
	}
}
